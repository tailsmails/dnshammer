module main

import os
import time
import rand

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

fn C.gethostbyname(name &u8) voidptr
fn C.socket(domain int, @type int, protocol int) int
fn C.close(fd int) int
fn C.connect(fd int, addr voidptr, addrlen u32) int
fn C.send(fd int, buf voidptr, len usize, flags int) isize
fn C.recv(fd int, buf voidptr, len usize, flags int) isize
fn C.recvfrom(fd int, buf voidptr, len usize, flags int, src_addr voidptr, addrlen voidptr) isize
fn C.sendto(fd int, buf voidptr, len usize, flags int, dest_addr voidptr, addrlen u32) isize
fn C.setsockopt(fd int, level int, optname int, optval voidptr, optlen u32) int
fn C.htons(v u16) u16
fn C.inet_pton(af int, src &u8, dst voidptr) int
fn C.getsockname(fd int, addr voidptr, addrlen voidptr) int

struct C.sockaddr_in {
mut:
	sin_family u16
	sin_port   u16
	sin_addr   C.in_addr
}

struct C.in_addr {
mut:
	s_addr u32
}

struct SockTimeout {
mut:
	sec  i64
	usec i64
}

__global g_dns = ''
__global g_workers = 16
__global window = 100
__global g_hs_window = 10
__global g_chunk_size = 5
__global g_tk_len = 6
__global g_fallback_notified = false
__global g_seed = u64(0)

const status_success = 0b1110
const status_success_n = 0b1100
const status_success_alt = 0b1010
const status_error = 0b0001
const status_ok = 0b1000
const status_start = 0b0100
const status_ready = 0b0011
const status_stop = 0b0010
const status_confirm_stop = 0b1101

fn get_ts() i64 {
	return time.now().unix_milli()
}

struct PhaseInfo {
	cycle_start i64
	phase       int
	phase_end   i64
	t1_len      i64
	t2_len      i64
	tk_len      i64
}

fn generate_secure_label(seed u64, prefix string, idx int, variant int, cts i64) string {
	mut hash := u64(14695981039346656037)
	prime := u64(1099511628211)
	
	hash ^= seed
	hash *= prime
	
	hash ^= u64(cts)
	hash *= prime
	
	for b in prefix.bytes() {
		hash ^= u64(b)
		hash *= prime
	}
	
	hash ^= u64(idx)
	hash *= prime
	
	hash ^= u64(variant)
	hash *= prime
	
	chars := 'abcdefghijklmnopqrstuvwxyz0123456789'
	mut state := hash
	mut label := ''
	for _ in 0 .. 8 {
		char_idx := int(state % u32(chars.len))
		label += chars[char_idx..char_idx+1]
		state /= u32(chars.len)
	}
	
	return label
}

fn get_phase_info(w int) PhaseInfo {
	now := get_ts()
	tk_duration := i64(g_tk_len) * 8 * 100
	total_cycle := i64(w) * 1000
	
	t_rem := total_cycle - tk_duration
	t1_duration := t_rem / 2
	t2_duration := t_rem / 2
	
	cycle_start := (now / total_cycle) * total_cycle
	elapsed := now % total_cycle
	
	mut phase := 0
	mut phase_end := cycle_start + t1_duration
	
	if elapsed < t1_duration {
		phase = 0
		phase_end = cycle_start + t1_duration
	} else if elapsed < t1_duration + t2_duration {
		phase = 1
		phase_end = cycle_start + t1_duration + t2_duration
	} else {
		phase = 2
		phase_end = cycle_start + total_cycle
	}
	
	return PhaseInfo{
		cycle_start: cycle_start
		phase: phase
		phase_end: phase_end
		t1_len: t1_duration
		t2_len: t2_duration
		tk_len: tk_duration
	}
}

fn wait_for_phase_start(target_phase int, w int) PhaseInfo {
	for {
		pi := get_phase_info(w)
		if pi.phase == target_phase {
			now := get_ts()
			mut phase_start := pi.cycle_start
			if pi.phase == 1 { phase_start += pi.t1_len }
			if pi.phase == 2 { phase_start += pi.t1_len + pi.t2_len }
			
			if now - phase_start < 1500 {
				return pi
			}
			
			sleep_ms := int(pi.phase_end - now) + 10
			time.sleep(sleep_ms * time.millisecond)
			continue
		}
		
		sleep_ms := int(pi.phase_end - get_ts()) + 10
		if sleep_ms > 0 {
			time.sleep(sleep_ms * time.millisecond)
		}
		
		new_pi := get_phase_info(w)
		if new_pi.phase == target_phase {
			return new_pi
		}
	}
	return get_phase_info(w)
}

fn char_idx(ch u8) int {
	if ch == ` ` { return 0 }
	return int(ch - `a`) + 1
}

fn huffman_encode(msg string) ([]u8, string) {
	codes := [u32(0), 5, 60, 25, 22, 1, 56, 57, 21, 7, 125, 124, 23, 26, 8, 6, 59, 254, 20, 9, 4, 24, 61, 27, 126, 58, 255]
	lens := [u8(3), 4, 6, 5, 5, 3, 6, 6, 5, 4, 7, 7, 5, 5, 4, 4, 6, 8, 5, 4, 4, 5, 6, 5, 7, 6, 8]

	mut filtered := []u8{}
	for ch in msg.bytes() {
		mut c := ch
		if c >= `A` && c <= `Z` { c += 32 }
		if (c >= `a` && c <= `z`) || c == ` ` { filtered << c }
	}

	mut bits := []u8{}
	for c in filtered {
		idx := char_idx(c)
		code := codes[idx]
		length := int(lens[idx])
		for b in 0 .. length {
			bits << u8((code >> u32(length - 1 - b)) & 1)
		}
	}

	mut result := []u8{}
	result << u8(filtered.len)
	mut i := 0
	for i < bits.len {
		mut bv := u8(0)
		for b in 0 .. 8 {
			bv = bv << 1
			if i + b < bits.len { bv |= bits[i + b] }
		}
		result << bv
		i += 8
	}
	return result, filtered.bytestr()
}

fn huffman_decode(data []u8) string {
	if data.len < 2 { return '' }
	nchars := int(data[0])
	syms := [u8(` `), `e`, `t`, `a`, `o`, `i`, `n`, `s`, `r`, `h`, `d`, `l`, `u`, `c`, `m`, `w`, `f`, `g`, `y`, `p`, `b`, `v`, `k`, `j`, `x`, `q`, `z`]
	fc := [0, 0, 0, 0, 4, 20, 56, 124, 254]
	fo := [0, 0, 0, 0, 2, 8, 16, 22, 25]
	cn := [0, 0, 0, 2, 6, 8, 6, 3, 2]

	mut bits := []u8{}
	for i in 1 .. data.len {
		for b in 0 .. 8 {
			bits << (data[i] >> u8(7 - b)) & 1
		}
	}

	mut result := []u8{}
	mut pos := 0
	for _ in 0 .. nchars {
		mut code := u32(0)
		mut found := false
		for l in 1 .. 9 {
			if pos >= bits.len { break }
			code = (code << 1) | u32(bits[pos])
			pos++
			if l >= 3 && int(code) >= fc[l] && int(code) - fc[l] < cn[l] {
				result << syms[fo[l] + int(code) - fc[l]]
				found = true
				break
			}
		}
		if !found { break }
	}
	return result.bytestr()
}

fn build_dns_query(host string, tx_id u16) []u8 {
	mut pkt := []u8{cap: 128}
	pkt << u8((tx_id >> 8) & 0xFF)
	pkt << u8(tx_id & 0xFF)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	for label in host.split('.') {
		pkt << u8(label.len)
		pkt << label.bytes()
	}
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x01)
	return pkt
}

fn ip_checksum(buf []u8) u16 {
	mut sum := u32(0)
	mut i := 0
	for i + 1 < buf.len {
		sum += (u32(buf[i]) << 8) | u32(buf[i + 1])
		i += 2
	}
	if i < buf.len { sum += u32(buf[i]) << 8 }
	for (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
	mut ans := u16(~sum & 0xffff)
	if ans == 0 { ans = 0xffff }
	return ans
}

fn udp_checksum(src_ip []u8, dst_ip []u8, udp_packet []u8) u16 {
	mut sum := u32(0)
	sum += (u32(src_ip[0]) << 8) | u32(src_ip[1])
	sum += (u32(src_ip[2]) << 8) | u32(src_ip[3])
	sum += (u32(dst_ip[0]) << 8) | u32(dst_ip[1])
	sum += (u32(dst_ip[2]) << 8) | u32(dst_ip[3])
	sum += 0x0011 
	sum += u32(udp_packet.len)
	mut i := 0
	for i + 1 < udp_packet.len {
		sum += (u32(udp_packet[i]) << 8) | u32(udp_packet[i + 1])
		i += 2
	}
	if i < udp_packet.len { sum += u32(udp_packet[i]) << 8 }
	for (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
	mut ans := u16(~sum & 0xffff)
	if ans == 0 { ans = 0xffff }
	return ans
}

fn build_raw_udp(src_ip []u8, dst_ip []u8, src_port u16, dst_port u16, ttl u8, payload []u8) []u8 {
	udp_len := 8 + payload.len
	total_len := 20 + udp_len
	mut pkt := []u8{len: total_len}

	pkt[0] = 0x45
	pkt[1] = 0x00
	pkt[2] = u8((total_len >> 8) & 0xff)
	pkt[3] = u8(total_len & 0xff)
	pkt[4] = 0xDE
	pkt[5] = 0xAD
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = ttl
	pkt[9] = 17 

	for i in 0 .. 4 {
		pkt[12 + i] = src_ip[i]
		pkt[16 + i] = dst_ip[i]
	}

	ip_ck := ip_checksum(pkt[..20])
	pkt[10] = u8((ip_ck >> 8) & 0xff)
	pkt[11] = u8(ip_ck & 0xff)

	pkt[20] = u8((src_port >> 8) & 0xff)
	pkt[21] = u8(src_port & 0xff)
	pkt[22] = u8((dst_port >> 8) & 0xff)
	pkt[23] = u8(dst_port & 0xff)
	pkt[24] = u8((udp_len >> 8) & 0xff)
	pkt[25] = u8(udp_len & 0xff)
	pkt[26] = 0
	pkt[27] = 0

	for i in 0 .. payload.len { pkt[28 + i] = payload[i] }

	udp_ck := udp_checksum(src_ip, dst_ip, pkt[20..])
	pkt[26] = u8((udp_ck >> 8) & 0xff)
	pkt[27] = u8(udp_ck & 0xff)

	return pkt
}

fn send_raw_packet(dst_ip []u8, dst_port u16, pkt []u8) bool {
	$if !windows {
		raw_fd := C.socket(C.AF_INET, C.SOCK_RAW, 255)
		if raw_fd < 0 { return false }
		
		mut one := int(1)
		C.setsockopt(raw_fd, C.IPPROTO_IP, C.IP_HDRINCL, &one, sizeof(one))
		
		mut dest := [16]u8{}
		dest[0] = 2 
		dest[2] = u8(dst_port >> 8)
		dest[3] = u8(dst_port & 0xFF)
		dest[4] = dst_ip[0]
		dest[5] = dst_ip[1]
		dest[6] = dst_ip[2]
		dest[7] = dst_ip[3]
		
		C.sendto(raw_fd, voidptr(pkt.data), pkt.len, 0, voidptr(&dest), u32(16))
		C.close(raw_fd)
		return true
	}
	return false
}

fn get_local_ip(dns_ip string) []u8 {
	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	mut sa := C.sockaddr_in{}
	sa.sin_family = u16(C.AF_INET)
	sa.sin_port = C.htons(53)
	C.inet_pton(C.AF_INET, dns_ip.str, &sa.sin_addr)
	C.connect(fd, &sa, sizeof(sa))
	
	mut local_sa := C.sockaddr_in{}
	mut sa_len := u32(sizeof(local_sa))
	C.getsockname(fd, &local_sa, &sa_len)
	C.close(fd)
	
	ptr := unsafe { &u8(&local_sa.sin_addr.s_addr) }
	return [unsafe{ptr[0]}, unsafe{ptr[1]}, unsafe{ptr[2]}, unsafe{ptr[3]}]
}

fn resolve_udp(host string, wait_for_reply bool) !i64 {
	$if windows { return error('udp resolve not implemented on windows') }
	
	mut sa := C.sockaddr_in{}
	sa.sin_family = u16(C.AF_INET)
	sa.sin_port = C.htons(53)
	if C.inet_pton(C.AF_INET, g_dns.str, &sa.sin_addr) <= 0 {
		return error('invalid dns ip')
	}

	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	if fd < 0 { return error('failed to create socket') }

	if C.connect(fd, &sa, sizeof(sa)) < 0 {
		C.close(fd)
		return error('connect failed')
	}

	tx_id := u16(rand.intn(65535) or { 0 })
	dns_payload := build_dns_query(host, tx_id)

	timeout_sec := if wait_for_reply { 2 } else { 0 }
	timeout_usec := if wait_for_reply { 0 } else { 10000 }
	tv := SockTimeout{sec: timeout_sec, usec: i64(timeout_usec)}
	C.setsockopt(fd, C.SOL_SOCKET, C.SO_RCVTIMEO, &tv, sizeof(tv))

	sw := time.new_stopwatch()
	if C.send(fd, dns_payload.data, dns_payload.len, 0) < 0 {
		C.close(fd)
		return error('send failed')
	}

	if !wait_for_reply {
		C.close(fd)
		return sw.elapsed().microseconds()
	}

	mut buf := []u8{len: 512}
	n := C.recv(fd, buf.data, 512, 0)
	elapsed := sw.elapsed().microseconds()
	C.close(fd)

	if n < 0 { return error('timeout') }
	return elapsed
}

fn resolve_raw(host string) !i64 {
	$if windows { return error('raw sockets not supported on windows') }
	
	mut dst_ip := []u8{len: 4}
	mut ip_parts := g_dns.split('.')
	if ip_parts.len == 4 {
		for i in 0 .. 4 { dst_ip[i] = u8(ip_parts[i].int()) }
	} else { return error('invalid dns ip') }

	src_ip := get_local_ip(g_dns)
	src_port := u16(rand.intn(50000) or { 10000 } + 10000)
	tx_id := u16(rand.intn(65535) or { 0 })

	dns_payload := build_dns_query(host, tx_id)
	raw_pkt := build_raw_udp(src_ip, dst_ip, src_port, 53, 64, dns_payload)

	rx_fd := C.socket(C.AF_INET, C.SOCK_RAW, 17)
	if rx_fd < 0 { return error('requires root for raw socket') }
	
	tv := SockTimeout{sec: 2, usec: 0}
	C.setsockopt(rx_fd, C.SOL_SOCKET, C.SO_RCVTIMEO, &tv, sizeof(tv))

	sw := time.new_stopwatch()
	send_raw_packet(dst_ip, 53, raw_pkt)
	
	mut buf := []u8{len: 2048}
	for {
		n := C.recvfrom(rx_fd, buf.data, 2048, 0, 0, 0)
		if n < 0 { break }
		
		if n > 28 {
			ip_hlen := (buf[0] & 0x0F) * 4
			if buf[9] == 17 { 
				src_port_rx := (u16(buf[ip_hlen]) << 8) | u16(buf[ip_hlen+1])
				dst_port_rx := (u16(buf[ip_hlen+2]) << 8) | u16(buf[ip_hlen+3])
				
				if src_port_rx == 53 && dst_port_rx == src_port {
					elapsed := sw.elapsed().microseconds()
					C.close(rx_fd)
					return elapsed
				}
			}
		}
		if sw.elapsed().milliseconds() > 2000 { break }
	}
	
	C.close(rx_fd)
	return error('timeout')
}

fn resolve(host string, wait_for_reply bool) !i64 {
	if g_dns.len > 0 {
		return resolve_raw(host) or {
			if !g_fallback_notified {
				println('[*] Raw sockets failed (root required?), falling back to UDP mode')
				g_fallback_notified = true
			}
			return resolve_udp(host, wait_for_reply)
		}
	}
	sw := time.new_stopwatch()
	_ := C.gethostbyname(host.str)
	elapsed := sw.elapsed().microseconds()
	if elapsed > 5000000 { return error('timeout') }
	return elapsed
}

fn resolve_safe(host string) i64 {
	for attempt in 0 .. 3 {
		t := resolve(host, true) or {
			time.sleep((100 + attempt * 200) * time.millisecond)
			continue
		}
		return t
	}
	return -1
}

@[noreturn]
fn die(s string) {
	eprintln('[!] ${s}')
	exit(1)
}

fn send_bit_task(base string, prefix string, idx int, cts i64, seed u64) {
	label1 := generate_secure_label(seed, prefix, idx, 0, cts)
	label2 := generate_secure_label(seed, prefix, idx, 1, cts)
	label3 := generate_secure_label(seed, prefix, idx, 2, cts)

	for _ in 0 .. 5 {
		resolve('${label1}.${base}', false) or { return }
		resolve('${label2}.${base}', false) or { return }
		resolve('${label3}.${base}', false) or { return }
	}
}

fn send_bits(base string, prefix string, start_idx int, bits []u8, deadline i64, cts i64) bool {
	mut threads := []thread{}
	for i, b in bits {
		if get_ts() > deadline { break }
		idx := start_idx + i
		if b == 0 {
			threads << spawn send_bit_task(base, prefix, idx, cts, g_seed)
		}
		if threads.len >= g_workers {
			threads.wait()
			threads = []thread{}
		}
	}
	threads.wait()
	return get_ts() <= deadline
}

struct BitResult {
	idx int
	bit u8
}

fn read_bit_worker(base string, prefix string, idx int, thr i64, cts i64, seed u64) BitResult {
	label1 := generate_secure_label(seed, prefix, idx, 0, cts)
	label2 := generate_secure_label(seed, prefix, idx, 1, cts)
	label3 := generate_secure_label(seed, prefix, idx, 2, cts)

	t1 := resolve_safe('${label1}.${base}')
	t2 := resolve_safe('${label2}.${base}')
	t3 := resolve_safe('${label3}.${base}')

	mut t := t1
	if t2 >= 0 && (t < 0 || t2 < t) { t = t2 }
	if t3 >= 0 && (t < 0 || t3 < t) { t = t3 }
	
	val := if t < 0 { u8(1) } else if t <= thr { u8(0) } else { u8(1) }
	return BitResult{idx: idx, bit: val}
}

fn derive_seed_from_password(password string) u64 {
	mut hash := u64(14695981039346656037)
	prime := u64(1099511628211)
	for b in password.bytes() {
		hash ^= u64(b)
		hash *= prime
	}
	return hash
}

fn read_bits(base string, prefix string, start_idx int, num_bits int, thr i64, deadline i64, cts i64) ![]u8 {
	if get_ts() > deadline { return error('deadline exceeded') }
	
	mut threads := []thread BitResult{}
	for i in 0 .. num_bits {
		idx := start_idx + i
		threads << spawn read_bit_worker(base, prefix, idx, thr, cts, g_seed)
	}
	
	results := threads.wait()
	
	mut sorted_res := []u8{len: num_bits}
	for res in results {
		pos := res.idx - start_idx
		if pos >= 0 && pos < num_bits {
			sorted_res[pos] = res.bit
		}
	}
	return sorted_res
}

fn checksum_3bit(idx u8, payload []u8) u8 {
	mut val := u32(idx & 3)
	for b in payload {
		val = (val << 1) | u32(b & 1)
	}
	mut checksum := u32(0)
	mut temp := val
	for temp > 0 {
		checksum ^= (temp & 7)
		temp >>= 3
	}
	return u8((checksum ^ 5) & 7)
}

fn crc8(data []u8) u8 {
	mut crc := u8(0)
	for b in data {
		crc ^= b
		for _ in 0 .. 8 {
			if (crc & 0x80) != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

fn pack_bits(bits []u8) []u8 {
	mut res := []u8{}
	mut i := 0
	for i < bits.len {
		mut b := u8(0)
		for j in 0 .. 8 {
			b = b << 1
			if i + j < bits.len {
				b |= bits[i + j]
			}
		}
		res << b
		i += 8
	}
	return res
}

fn calibrate(base string) !i64 {
	println('[*] calibrating...')
	for attempt in 0 .. 5 {
		mut fast_arr := []i64{}
		mut slow_arr := []i64{}
		for _ in 0 .. 5 {
			f := resolve_safe('c0.${base}')
			if f >= 0 { fast_arr << f }
			time.sleep(30 * time.millisecond)
		}
		for _ in 0 .. 5 {
			s := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
			if s >= 0 { slow_arr << s }
			time.sleep(30 * time.millisecond)
		}
		if fast_arr.len < 3 || slow_arr.len < 3 { 
			time.sleep(500 * time.millisecond)
			continue 
		}
		fast_arr.sort()
		slow_arr.sort()
		fast_med := fast_arr[fast_arr.len / 2]
		slow_med := slow_arr[slow_arr.len / 2]
		
		gap := slow_med - fast_med
		if gap < 8000 { 
			println('[*] calibration gap too small (${gap}µs), retrying... (attempt ${attempt + 1}/5)')
			time.sleep(1000 * time.millisecond)
			continue
		}
		
		mut thr := (fast_med + slow_med) / 2
		if thr < 1000 { thr = 1000 }
		println('[*] calibrated threshold: ${thr}µs (Fast: ${fast_med}, Slow: ${slow_med}, Gap: ${gap}µs)')
		return thr
	}
	return error('calibration failed permanently: unstable network or aggressive caching')
}

fn bits_to_int(bits []u8) u32 {
	mut val := u32(0)
	for b in bits {
		val = (val << 1) | u32(b)
	}
	return val
}

fn int_to_bits(val int, num_bits int) []u8 {
	mut res := []u8{len: num_bits}
	for i in 0 .. num_bits {
		res[num_bits - 1 - i] = u8((val >> i) & 1)
	}
	return res
}

fn send_mode(base string, msg string) {
	mut thr := calibrate(base) or { die('calibration failed') }
	
	mut raw_data, filtered := huffman_encode(msg)
	h := crc8(filtered.bytes()) 
	
	mut data := []u8{}
	data << h
	data << raw_data
	
	mut data_bits := []u8{}
	for b in data {
		data_bits << int_to_bits(int(b), 8)
	}

	println('[tx] "${msg}" -> "${filtered}" (${filtered.len} chars)')
	println('[tx] Message CRC-8 Hash: ${h:02X}')
	println('[tx] ${data.len} total wire bytes (incl. Hash)')
	println('[tx] chunk size: ${g_chunk_size} bits')
	
	pi_check := get_phase_info(window)
	
	wire_chunk_bits := 2 + 3 + g_chunk_size + 2 + 4
	estimated_time := i64(wire_chunk_bits) * 600
	
	if estimated_time > pi_check.t1_len {
		die('Window too small for chunk size ${g_chunk_size} bits. T1=${pi_check.t1_len}ms, need ~${estimated_time}ms')
	}

	println('[tx] Waiting for receiver READY signal (0111)...')
	for {
		pi_tk := wait_for_phase_start(2, g_hs_window)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		t_fast := resolve_safe('c0.${base}')
		t_slow := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
		if t_fast >= 0 && t_slow >= 0 && t_slow > t_fast {
			target_thr := (t_fast + t_slow) / 2
			mut next_thr := (thr * 8 + target_thr * 2) / 10
			
			if next_thr > thr + 15000 {
				next_thr = thr + 15000
			}
			if next_thr < thr - 15000 {
				next_thr = thr - 15000
			}
			thr = next_thr
			println('[tx] Dynamic threshold updated (LPF+SRL): ${thr}µs (Fast: ${t_fast}, Slow: ${t_slow})')
		}
		
		status_bits := read_bits(base, "r", 0, 4, thr, tk_mid, cts_tk) or { []u8{} }
		
		if status_bits.len == 4 {
			status := bits_to_int(status_bits)
			if status == status_ready {
				println('[tx] Receiver is READY. Acknowledging and starting.')
				
				println('[tx] Sending START acknowledgement (3 cycles)...')
				time.sleep(int(pi_tk.phase_end - get_ts()) + 10)

				for _ in 0 .. 3 {
					pi_t1_ack := wait_for_phase_start(0, g_hs_window)
					cts_ack := pi_t1_ack.cycle_start / 1000
					send_bits(base, "s", 0, int_to_bits(status_start, 4), pi_t1_ack.phase_end, cts_ack)
					
					pi_tk_ack := wait_for_phase_start(2, g_hs_window)
					remaining := int(pi_tk_ack.phase_end - get_ts())
					if remaining > 0 {
						time.sleep(remaining * time.millisecond)
					}
					time.sleep(10 * time.millisecond)
				}
				println('[tx] Handshake complete.')
				break
			}
		}
		
		remaining := int(pi_tk.phase_end - get_ts())
		if remaining > 0 {
			time.sleep(remaining * time.millisecond)
		}
		time.sleep(100 * time.millisecond)
	}

	mut pos := 0
	mut chunk_idx := u8(0)
	mut resending := false
	mut first_success := false
	for pos < data_bits.len {
		pi := wait_for_phase_start(0, window)
		cts := pi.cycle_start / 1000
		
		mut end := pos + g_chunk_size
		if end > data_bits.len { end = data_bits.len }
		
		mut payload_bits := data_bits[pos..end].clone()
		for payload_bits.len < g_chunk_size { payload_bits << u8(0) }
		
		roll_idx := u8(chunk_idx & 3)
		ch_hash := checksum_3bit(roll_idx, payload_bits)
		
		term := if end < data_bits.len { u8(1) } else { u8(2) }

		mut chunk_bits := []u8{}
		chunk_bits << int_to_bits(int(roll_idx), 2)
		chunk_bits << int_to_bits(int(ch_hash), 3)
		chunk_bits << payload_bits
		chunk_bits << int_to_bits(int(term), 2)
		
		if resending {
			println('[tx] Resending chunk #${chunk_idx} (RollIdx: ${roll_idx}) bits [${pos}..${end}]')
		} else {
			println('[tx] Sending chunk #${chunk_idx} (RollIdx: ${roll_idx}) bits [${pos}..${end}]')
		}
		
		t1_mid := pi.cycle_start + (pi.t1_len / 2)
		if !send_bits(base, "d", 0, chunk_bits, t1_mid, cts) {
			println('[!] T1 Segment 1 timeout')
		}
		for get_ts() < t1_mid { time.sleep(10 * time.millisecond) }
		if !send_bits(base, "d", 0, chunk_bits, pi.phase_end, cts) {
			println('[!] T1 Segment 2 timeout')
		}
		
		tk_sig := if first_success { status_ok } else { status_start }
		tk_sig_bits := int_to_bits(int(tk_sig), 4)
		send_bits(base, "s", 0, tk_sig_bits, pi.phase_end, cts)
		
		pi_tk := wait_for_phase_start(2, window)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		send_bits(base, "s", 0, int_to_bits(tk_sig, 4), tk_mid, cts_tk)
		
		t_fast := resolve_safe('c0.${base}')
		t_slow := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
		if t_fast >= 0 && t_slow >= 0 && t_slow > t_fast {
			thr = (t_fast + t_slow) / 2
			println('[tx] Dynamic threshold updated: ${thr}µs (Fast: ${t_fast}, Slow: ${t_slow})')
		}
		
		mut status := u32(0)
		mut got_status := false
		status_bits := read_bits(base, "r", 0, 4, thr, tk_mid, cts_tk) or { []u8{} }
		if status_bits.len == 4 {
			status = bits_to_int(status_bits)
			if status != 0b1111 {
				got_status = true
			}
		}
		
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		
		if got_status {
			println('[tx] Receiver status: ${status:04b}')
			if status == status_ready {
				println('[tx] Receiver appears to be in handshake mode. Re-acknowledging...')
				pi_tk_ra := wait_for_phase_start(2, window)
				cts_tk_ra := pi_tk_ra.cycle_start / 1000
				tk_mid_ra := pi_tk_ra.cycle_start + pi_tk_ra.t1_len + pi_tk_ra.t2_len + (pi_tk_ra.tk_len / 2)
				send_bits(base, "s", 0, int_to_bits(status_start, 4), tk_mid_ra, cts_tk_ra)
				resending = true
				continue
			}
			if status == status_stop {
				println('[tx] Receiver requested stop, but we have more data (${pos}/${data_bits.len}). Retransmitting.')
				resending = true
				continue
			}
			if status == 0b1111 {
				println('[tx] No signal from receiver (0b1111).')
				resending = true
				continue
			}
			if status == status_success || status == status_ok || status == status_start || status == status_success_n || status == status_success_alt {
				pos = end
				chunk_idx++
				resending = false
				first_success = true
			} else {
				println('[tx] Receiver reported error. Will resend.')
				resending = true
			}
		} else {
			println('[tx] No status/No signal from receiver.')
			resending = true 
		}
	}
}

fn rec_mode(base string) {
	mut thr := calibrate(base) or { die('calibration failed') }
	pi_check := get_phase_info(window)
	
	wire_chunk_bits := 2 + 3 + g_chunk_size + 2
	estimated_time := i64(wire_chunk_bits) * 550
	if estimated_time > pi_check.t2_len {
		die('Window too small for chunk size ${g_chunk_size} bits. T2=${pi_check.t2_len}ms, need ~${estimated_time}ms')
	}

	mut hash_received := false
	mut final_data_bits := []u8{}
	mut finished := false
	mut last_accepted_idx := -1
	mut first_chunk := true

	println('[rx] Sending READY (0111) and waiting for START (1100)...')
	for {
		pi := wait_for_phase_start(1, g_hs_window)
		cts := pi.cycle_start / 1000
		t2_start := pi.cycle_start + pi.t1_len
		t2_third := pi.t2_len / 3
		ready_time := t2_start + 2 * t2_third
		for get_ts() < ready_time { time.sleep(100 * time.millisecond) }
		send_bits(base, "r", 0, int_to_bits(status_ready, 4), pi.phase_end, cts)
		pi_tk := wait_for_phase_start(2, g_hs_window)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		conf_bits := read_bits(base, "s", 0, 4, thr, tk_mid, cts_tk) or { []u8{} }
		if conf_bits.len == 4 {
			status := bits_to_int(conf_bits)
			if status == status_start {
				println('[rx] START detected. Entering reading loop.')
				break
			}
		}
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		send_bits(base, "r", 0, int_to_bits(status_ready, 4), pi_tk.phase_end, cts)
	}

	for !finished {
		pi := wait_for_phase_start(1, window)
		cts := pi.cycle_start / 1000
		
		t_fast := resolve_safe('c0.${base}')
		t_slow := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
		if t_fast >= 0 && t_slow >= 0 && t_slow > t_fast {
			target_thr := (t_fast + t_slow) / 2
			mut next_thr := (thr * 8 + target_thr * 2) / 10
			
			if next_thr > thr + 15000 {
				next_thr = thr + 15000
			}
			if next_thr < thr - 15000 {
				next_thr = thr - 15000
			}
			thr = next_thr
			println('[rx] Dynamic threshold updated (LPF+SRL): ${thr}µs (Fast: ${t_fast}, Slow: ${t_slow})')
		}
		
		println('[rx] Cycle start, reading chunk...')
		num_bits := wire_chunk_bits
		
		mut success := true
		bits := read_bits(base, "d", 0, num_bits, thr, pi.phase_end, cts) or {
			println('[!] T2 timeout or read failure')
			success = false
			[]u8{}
		}
		
		if success && bits.len == num_bits {
			roll_idx := u8(bits_to_int(bits[0..2]))
			chunk_hash := u8(bits_to_int(bits[2..5]))
			payload_bits := bits[5 .. 5 + g_chunk_size].clone()
			terminator := u8(bits_to_int(bits[5 + g_chunk_size .. 5 + g_chunk_size + 2]))

			is_eom := terminator == 2
			is_chunk_end := terminator == 1

			if is_chunk_end || is_eom {
				actual_chunk_hash := checksum_3bit(roll_idx, payload_bits)

				if actual_chunk_hash == chunk_hash {
					println('[rx] Chunk verified! RollIdx: ${roll_idx}, Term: ${terminator:02b} (hash OK)')
					
					if first_chunk {
						final_data_bits << payload_bits
						hash_received = true
						last_accepted_idx = int(roll_idx)
						first_chunk = false
						println('[rx] First chunk accepted.')
					} else if int(roll_idx) == (last_accepted_idx + 1) % 4 {
						final_data_bits << payload_bits
						hash_received = true
						last_accepted_idx = int(roll_idx)
						println('[rx] Chunk accepted.')
						if is_eom {
							finished = true
						}
					} else if int(roll_idx) == last_accepted_idx {
						println('[rx] Chunk RollIdx #${roll_idx} already accepted, skipping duplicate save.')
					} else {
						println('[rx] Unexpected RollIdx: ${roll_idx} (expected ${(last_accepted_idx + 1) % 4} or ${last_accepted_idx})')
						success = false
					}
				} else {
					println('[rx] Chunk hash mismatch! Expected: ${chunk_hash:03b}, Actual: ${actual_chunk_hash:03b}')
					success = false
				}
			} else {
				println('[rx] Invalid chunk terminator: ${terminator:02b}')
				success = false
			}
		} else {
			success = false
		}
		
		t2_start := pi.cycle_start + pi.t1_len
		t2_third := pi.t2_len / 3
		status_report_time := t2_start + 2 * t2_third
		
		for get_ts() < status_report_time { time.sleep(100 * time.millisecond) }
		
		status_val := if success { status_success } else { status_error }
		send_bits(base, "r", 0, int_to_bits(status_val, 4), pi.phase_end, cts)
		
		pi_tk := wait_for_phase_start(2, window)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		
		tk_status := if !hash_received {
			status_ready
		} else if success {
			if rand.intn(2) or { 0 } == 0 { status_success_n } else { status_success_alt }
		} else {
			status_error
		}
		send_bits(base, "r", 0, int_to_bits(tk_status, 4), pi_tk.phase_end, cts_tk)
		
		if !success {
			println('[rx] Error reported. Expecting retransmission.')
		}
	}
	
	final_data := pack_bits(final_data_bits)
	if final_data.len > 1 {
		expected_hash := final_data[0]
		payload_data := final_data[1..].clone()
		decoded := huffman_decode(payload_data)
		println('\n[rx] Final message: "${decoded}"')
		actual_hash := crc8(decoded.bytes())
		if actual_hash != expected_hash {
			println('[!] Final message hash mismatch! Expected: ${expected_hash:02X}, Actual: ${actual_hash:02X}')
		} else {
			println('[rx] Hash verified successfully.')
		}
	} else {
		println('[!] No data received.')
	}
}

fn main() {
	mut args := []string{}
	mut i := 1
	mut pass_str := 'default_secure_passphrase'

	for i < os.args.len {
		if os.args[i] == '--dns' && i + 1 < os.args.len {
			g_dns = os.args[i + 1]
			i += 2
		} else if os.args[i] == '--workers' && i + 1 < os.args.len {
			g_workers = os.args[i + 1].int()
			if g_workers < 1 { g_workers = 1 }
			i += 2
		} else if os.args[i] == '--window' && i + 1 < os.args.len {
			window = os.args[i + 1].int()
			if window < 1 { window = 1 }
			i += 2
		} else if os.args[i] == '--hs-window' && i + 1 < os.args.len {
			g_hs_window = os.args[i + 1].int()
			if g_hs_window < 1 { g_hs_window = 1 }
			i += 2
		} else if os.args[i] == '--chunk-size' && i + 1 < os.args.len {
			g_chunk_size = os.args[i + 1].int()
			if g_chunk_size < 1 { g_chunk_size = 1 }
			i += 2
		} else if os.args[i] == '--tk-len' && i + 1 < os.args.len {
			g_tk_len = os.args[i + 1].int()
			if g_tk_len < 1 { g_tk_len = 1 }
			i += 2
		} else if os.args[i] == '--pass' && i + 1 < os.args.len {
			pass_str = os.args[i + 1]
			println('[*] Secret key = ${pass_str}')
			i += 2
		} else {
			args << os.args[i]
			i += 1
		}
	}
	
	g_seed = derive_seed_from_password(pass_str)

	if g_dns.len > 0 { println('[*] dns server: ${g_dns}') }
	
	if args.len < 1 {
		eprintln('dnsh [--dns SERVER] [--workers N] [--window SEC] [--chunk-size BITS] [--tk-len N] <send|rec> [domain] [msg]')
		eprintln('  sudo ./dnsh --dns 8.8.8.8 send x.com "hello world"')
		eprintln('  sudo ./dnsh --dns 8.8.8.8 rec  x.com')
		exit(1)
	}
	match args[0] {
		'send' {
			d := if args.len > 1 { args[1] } else { 'x.com' }
			m := if args.len > 2 { args[2] } else { 'hi' }
			send_mode(d, m)
		}
		'rec' {
			d := if args.len > 1 { args[1] } else { 'x.com' }
			rec_mode(d)
		}
		else { die('send or rec') }
	}
}
