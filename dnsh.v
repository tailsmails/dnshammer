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
__global g_workers = 4
__global window = 100
__global g_chunk_size = 5
__global g_tk_len = 6
__global g_fallback_notified = false

const magic_eof = u16(0xFFFF)
const magic_no_signal = u16(0x0000)
const magic_eom = u16(0xAAAA)
const magic_chunk_end = u16(0xEEEE)

const status_success = 0b0110
const status_success_n = 0b0100
const status_error = 0b1001
const status_ok = 0b1010
const status_start = 0b1100
const status_stop = 0b0001
const status_confirm_stop = 0b1000

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

fn get_phase_info() PhaseInfo {
	now := get_ts()
	tk_duration := i64(g_tk_len) * 8 * 100
	total_cycle := i64(window) * 1000
	
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

fn wait_for_phase(target_phase int) PhaseInfo {
	for {
		pi := get_phase_info()
		if pi.phase == target_phase {
			return pi
		}
		sleep_ms := int(pi.phase_end - get_ts()) + 10
		if sleep_ms > 0 {
			time.sleep(sleep_ms * time.millisecond)
		}
	}
	return get_phase_info()
}

fn char_idx(ch u8) int {
	if ch == ` ` { return 0 }
	return int(ch - `a`) + 1
}

fn huffman_encode(msg string) ([]u8, string) {
	codes :=[u32(0), 5, 60, 25, 22, 1, 56, 57, 21, 7, 125, 124, 23, 26, 8, 6, 59, 254, 20, 9, 4, 24, 61, 27, 126, 58, 255]
	lens :=[u8(3), 4, 6, 5, 5, 3, 6, 6, 5, 4, 7, 7, 5, 5, 4, 4, 6, 8, 5, 4, 4, 5, 6, 5, 7, 6, 8]

	mut filtered :=[]u8{}
	for ch in msg.bytes() {
		mut c := ch
		if c >= `A` && c <= `Z` { c += 32 }
		if (c >= `a` && c <= `z`) || c == ` ` { filtered << c }
	}

	mut bits :=[]u8{}
	for c in filtered {
		idx := char_idx(c)
		code := codes[idx]
		length := int(lens[idx])
		for b in 0 .. length {
			bits << u8((code >> u32(length - 1 - b)) & 1)
		}
	}

	mut result :=[]u8{}
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

fn huffman_decode(data[]u8) string {
	if data.len < 2 { return '' }
	nchars := int(data[0])
	syms :=[u8(` `), `e`, `t`, `a`, `o`, `i`, `n`, `s`, `r`, `h`, `d`, `l`, `u`, `c`, `m`, `w`, `f`, `g`, `y`, `p`, `b`, `v`, `k`, `j`, `x`, `q`, `z`]
	fc :=[0, 0, 0, 0, 4, 20, 56, 124, 254]
	fo :=[0, 0, 0, 0, 2, 8, 16, 22, 25]
	cn :=[0, 0, 0, 2, 6, 8, 6, 3, 2]

	mut bits :=[]u8{}
	for i in 1 .. data.len {
		for b in 0 .. 8 {
			bits << (data[i] >> u8(7 - b)) & 1
		}
	}

	mut result :=[]u8{}
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

fn build_dns_query(host string, tx_id u16)[]u8 {
	mut pkt :=[]u8{cap: 128}
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

fn ip_checksum(buf[]u8) u16 {
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

fn udp_checksum(src_ip[]u8, dst_ip []u8, udp_packet[]u8) u16 {
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

fn build_raw_udp(src_ip []u8, dst_ip[]u8, src_port u16, dst_port u16, ttl u8, payload []u8)[]u8 {
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

fn send_raw_packet(dst_ip[]u8, dst_port u16, pkt[]u8) bool {
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

fn get_local_ip(dns_ip string)[]u8 {
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

fn resolve_udp(host string) !i64 {
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

	tv := SockTimeout{sec: 2, usec: 0}
	C.setsockopt(fd, C.SOL_SOCKET, C.SO_RCVTIMEO, &tv, sizeof(tv))

	sw := time.new_stopwatch()
	if C.send(fd, dns_payload.data, dns_payload.len, 0) < 0 {
		C.close(fd)
		return error('send failed')
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
	
	mut dst_ip :=[]u8{len: 4}
	mut ip_parts := g_dns.split('.')
	if ip_parts.len == 4 {
		for i in 0 .. 4 { dst_ip[i] = u8(ip_parts[i].int()) }
	} else { return error('invalid dns ip') }

	src_ip := get_local_ip(g_dns)
	src_port := u16(rand.intn(50000) or { 10000 } + 10000)
	tx_id := u16(rand.intn(65535) or { 0 })

	dns_payload := build_dns_query(host, tx_id)
	raw_pkt := build_raw_udp(src_ip, dst_ip, src_port, 53, 64, dns_payload)

	rx_fd := C.socket(C.AF_INET, C.SOCK_RAW, 17) // IPPROTO_UDP
	if rx_fd < 0 { return error('requires root for raw socket') }
	
	tv := SockTimeout{sec: 2, usec: 0}
	C.setsockopt(rx_fd, C.SOL_SOCKET, C.SO_RCVTIMEO, &tv, sizeof(tv))

	sw := time.new_stopwatch()
	send_raw_packet(dst_ip, 53, raw_pkt)
	
	mut buf :=[]u8{len: 2048}
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

fn resolve(host string) !i64 {
	if g_dns.len > 0 {
		return resolve_raw(host) or {
			if !g_fallback_notified {
				println('[*] Raw sockets failed (root required?), falling back to UDP mode')
				g_fallback_notified = true
			}
			return resolve_udp(host)
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
		t := resolve(host) or {
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

fn send_bits(base string, prefix string, start_idx int, bits []u8, deadline i64, cts i64) bool {
	for i, b in bits {
		if get_ts() > deadline { return false }
		idx := start_idx + i
		if b == 0 {
			resolve('${prefix}${idx}${cts}.${base}') or {}
			resolve('v${prefix}${idx}${cts}.${base}') or {}
			resolve('w${prefix}${idx}${cts}.${base}') or {}
		}
	}
	return true
}

fn read_bits(base string, prefix string, start_idx int, num_bits int, thr i64, deadline i64, cts i64) ![]u8 {
	mut res := []u8{}
	for i in 0 .. num_bits {
		if get_ts() > deadline { return error('deadline exceeded') }
		idx := start_idx + i
		
		t1 := resolve_safe('${prefix}${idx}${cts}.${base}')
		t2 := resolve_safe('v${prefix}${idx}${cts}.${base}')
		t3 := resolve_safe('w${prefix}${idx}${cts}.${base}')

		mut t := t1
		if t2 >= 0 && (t < 0 || t2 < t) { t = t2 }
		if t3 >= 0 && (t < 0 || t3 < t) { t = t3 }
		
		if t < 0 { return error('bit read failed') }
		res << (if t <= thr { u8(0) } else { u8(1) })
	}
	return res
}


fn calibrate(base string) !i64 {
	println('[*] calibrating...')
	mut fast_arr := []i64{}
	mut slow_arr := []i64{}
	for _ in 0 .. 5 {
		f := resolve_safe('c0.${base}')
		if f >= 0 { fast_arr << f }
		time.sleep(50 * time.millisecond)
	}
	for _ in 0 .. 5 {
		s := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
		if s >= 0 { slow_arr << s }
		time.sleep(50 * time.millisecond)
	}
	if fast_arr.len < 3 || slow_arr.len < 3 { return error('calibration failed') }
	fast_arr.sort()
	slow_arr.sort()
	fast_med := fast_arr[fast_arr.len / 2]
	slow_med := slow_arr[slow_arr.len / 2]
	gap := slow_med - fast_med
	if gap < 1000 { return error('gap too small') }
	mut thr := ((fast_med + slow_med + gap) / 3) - 500
	if thr < 1000 { thr = 1000 }
	println('[*] calibrated threshold: ${thr}µs')
	return thr
}

fn bits_to_int(bits []u8) u32 {
	mut val := u32(0)
	for b in bits {
		val = (val << 1) | u32(b)
	}
	return val
}

fn is_fuzzy_match(val u16, target u16) bool {
	mut matches := 0
	for i in 0 .. 4 {
		shift := i * 4
		if ((val >> shift) & 0xF) == ((target >> shift) & 0xF) {
			matches++
		}
	}
	return matches >= 3
}

fn int_to_bits(val int, num_bits int) []u8 {
	mut res := []u8{len: num_bits}
	for i in 0 .. num_bits {
		res[num_bits - 1 - i] = u8((val >> i) & 1)
	}
	return res
}

fn send_mode(base string, msg string) {
	thr := calibrate(base) or { die('calibration failed') }
	
	mut data, filtered := huffman_encode(msg)
	// Append AA AA (magic_eom)
	data << u8(magic_eom >> 8)
	data << u8(magic_eom & 0xFF)

	println('[tx] "${msg}" -> "${filtered}" (${filtered.len} chars)')
	println('[tx] ${data.len} total wire bytes (incl. EOM)')
	println('[tx] chunk size: ${g_chunk_size}')
	
	pi_check := get_phase_info()
	// Index (1) + Payload (g_chunk_size) + Terminator (2)
	wire_chunk_size := 1 + g_chunk_size + 2
	
	estimated_bits := wire_chunk_size * 8
	estimated_time := i64(estimated_bits) * 350
	if estimated_time > pi_check.t1_len {
		die('Window too small for chunk size ${g_chunk_size}. T1=${pi_check.t1_len}ms, need ~${estimated_time}ms')
	}

	mut pos := 0
	mut chunk_idx := u8(0)
	mut resending := false
	for pos < data.len {
		pi := wait_for_phase(0) // Wait for T1
		cts := pi.cycle_start / 1000
		
		mut end := pos + g_chunk_size
		if end > data.len { end = data.len }
		
		mut payload := data[pos..end].clone()
		// Padding payload to g_chunk_size
		for payload.len < g_chunk_size { payload << u8(0) }

		mut chunk := []u8{}
		chunk << chunk_idx
		chunk << payload
		
		if end < data.len {
			chunk << u8(magic_chunk_end >> 8)
			chunk << u8(magic_chunk_end & 0xFF)
		} else {
			chunk << u8(magic_eom >> 8)
			chunk << u8(magic_eom & 0xFF)
		}
		
		if resending {
			println('[tx] Resending chunk #${chunk_idx} [${pos}..${end}]')
		} else {
			println('[tx] Sending chunk #${chunk_idx} [${pos}..${end}]')
		}
		
		mut chunk_bits := []u8{}
		for b in chunk {
			chunk_bits << int_to_bits(int(b), 8)
		}
		
		if !send_bits(base, "d", 0, chunk_bits, pi.phase_end, cts) {
			println('[!] T1 timeout, chunk might be incomplete')
		}
		
		// TK window
		pi_tk := wait_for_phase(2)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		send_bits(base, "s", 0, int_to_bits(status_ok, 4), tk_mid, cts_tk)
		
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		
		mut status := u32(0)
		mut got_status := false
		for _ in 0 .. 3 {
			status_bits := read_bits(base, "r", 0, 4, thr, pi_tk.phase_end, cts_tk) or { continue }
			status = bits_to_int(status_bits)
			if status != 0b1111 {
				got_status = true
				break
			}
		}
		
		if got_status {
			println('[tx] Receiver status: ${status:04b}')
			if status == status_stop {
				println('[tx] Receiver requested stop. Confirming.')
				break
			}
			if status == status_success || status == status_ok || status == status_start || status == status_success_n {
				pos = end
				chunk_idx++
				resending = false
			} else {
				println('[tx] Receiver reported error. Will resend.')
				resending = true
			}
		} else {
			println('[tx] No status/No signal from receiver.')
			resending = true 
		}
	}
	
	println('[tx] Entering final termination handshake...')
	for attempt in 0 .. 10 {
		println('[tx] Termination handshake attempt #${attempt+1}...')
		pi_tk := wait_for_phase(2)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		status_bits := read_bits(base, "r", 0, 4, thr, pi_tk.phase_end, cts_tk) or { []u8{} }
		if status_bits.len == 4 {
			status := bits_to_int(status_bits)
			if status == status_stop {
				println('[tx] Received STOP. Sending CONFIRM.')
				pi_tk_next := wait_for_phase(2)
				cts_tk_next := pi_tk_next.cycle_start / 1000
				tk_mid_next := pi_tk_next.cycle_start + pi_tk_next.t1_len + pi_tk_next.t2_len + (pi_tk_next.tk_len / 2)
				send_bits(base, "s", 0, int_to_bits(status_confirm_stop, 4), tk_mid_next, cts_tk_next)
				println('[tx] Termination confirmed. Done.')
				return
			}
		}
		time.sleep(500 * time.millisecond)
	}
}

fn rec_mode(base string) {
	thr := calibrate(base) or { die('calibration failed') }
	pi_check := get_phase_info()
	// Index (1) + Payload (g_chunk_size) + Terminator (2)
	wire_chunk_size := 1 + g_chunk_size + 2
	estimated_bits := wire_chunk_size * 8
	estimated_time := i64(estimated_bits) * 550
	if estimated_time > pi_check.t2_len {
		die('Window too small for chunk size ${g_chunk_size}. T2=${pi_check.t2_len}ms, need ~${estimated_time}ms')
	}

	mut final_data := []u8{}
	mut finished := false
	mut last_accepted_idx := -1

	for !finished {
		pi := wait_for_phase(1) // Wait for T2
		cts := pi.cycle_start / 1000
		println('[rx] Cycle start, reading chunk...')
		
		num_bits := wire_chunk_size * 8
		
		mut success := true
		bits := read_bits(base, "d", 0, num_bits, thr, pi.phase_end, cts) or {
			println('[!] T2 timeout or read failure')
			success = false
			[]u8{}
		}
		
		if success && bits.len == num_bits {
			mut chunk_full := []u8{}
			for i in 0 .. wire_chunk_size {
				chunk_full << u8(bits_to_int(bits[i*8 .. (i+1)*8]))
			}
			
			chunk_idx := chunk_full[0]
			payload := chunk_full[1..wire_chunk_size-2].clone()
			terminator := (u16(chunk_full[wire_chunk_size - 2]) << 8) | u16(chunk_full[wire_chunk_size - 1])
			
			// Verify terminator with fuzzy matching
			is_eom := is_fuzzy_match(terminator, magic_eom)
			is_chunk_end := is_fuzzy_match(terminator, magic_chunk_end)

			if is_chunk_end || is_eom {
				println('[rx] Chunk #${chunk_idx} valid (terminator: ${terminator:04X})')
				
				if int(chunk_idx) > last_accepted_idx {
					mut chunk_data := payload.clone()
					
					if is_eom {
						finished = true
					}
					
					final_data << chunk_data
					last_accepted_idx = int(chunk_idx)
					println('[rx] Chunk accepted.')
				} else {
					println('[rx] Chunk #${chunk_idx} already accepted, skipping.')
				}
			} else {
				println('[rx] Invalid chunk terminator: ${terminator:04X}')
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
		
		// TK window
		pi_tk := wait_for_phase(2)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		
		tk_status := if success { status_start } else { status_error }
		send_bits(base, "r", 0, int_to_bits(tk_status, 4), pi_tk.phase_end, cts_tk)
		
		if !success {
			println('[rx] Error reported. Expecting retransmission.')
		}
	}
	
	decoded := huffman_decode(final_data)
	println('\n[rx] Final message: "${decoded}"')
	
	println('[rx] Entering termination handshake...')
	for _ in 0 .. 5 {
		pi := wait_for_phase(1)
		cts := pi.cycle_start / 1000
		
		t2_start := pi.cycle_start + pi.t1_len
		t2_third := pi.t2_len / 3
		status_report_time := t2_start + 2 * t2_third
		for get_ts() < status_report_time { time.sleep(100 * time.millisecond) }
		send_bits(base, "r", 0, int_to_bits(status_stop, 4), pi.phase_end, cts)
		
		// TK window
		pi_tk := wait_for_phase(2)
		cts_tk := pi_tk.cycle_start / 1000
		tk_mid := pi_tk.cycle_start + pi_tk.t1_len + pi_tk.t2_len + (pi_tk.tk_len / 2)
		
		conf_bits := read_bits(base, "s", 0, 4, thr, tk_mid, cts_tk) or { []u8{} }
		if conf_bits.len == 4 {
			conf_val := bits_to_int(conf_bits)
			if conf_val == status_confirm_stop {
				println('[rx] Sender confirmed stop. Terminating.')
				break
			}
		}
		
		for get_ts() < tk_mid { time.sleep(50 * time.millisecond) }
		send_bits(base, "r", 0, int_to_bits(status_stop, 4), pi_tk.phase_end, cts_tk)
	}
}

fn main() {
	mut args :=[]string{}
	mut i := 1
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
		} else if os.args[i] == '--chunk-size' && i + 1 < os.args.len {
			g_chunk_size = os.args[i + 1].int()
			if g_chunk_size < 1 { g_chunk_size = 1 }
			i += 2
		} else if os.args[i] == '--tk-len' && i + 1 < os.args.len {
			g_tk_len = os.args[i + 1].int()
			if g_tk_len < 1 { g_tk_len = 1 }
			i += 2
		} else {
			args << os.args[i]
			i += 1
		}
	}

	if g_dns.len > 0 { println('[*] dns server: ${g_dns}') }

	if args.len < 1 {
		eprintln('dnsh [--dns SERVER] [--workers N] [--window SEC] [--chunk-size N] [--tk-len N] <send|rec> [domain] [msg]')
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
