import heapq

# Final Alphabet (38 chars): space, a-z, 0-9, .
# Frequencies optimized for general text + alphanumeric identifiers
freqs = {
    ' ': 150, 'e': 100, 't': 80, 'a': 75, 'o': 70, 'i': 65, 'n': 65, 's': 60, 'r': 60, 'h': 50,
    'l': 40, 'd': 35, 'c': 30, 'u': 28, 'm': 25, 'w': 22, 'f': 20, 'g': 18, 'y': 18, 'p': 16,
    'b': 14, 'v': 10, 'k': 7, 'j': 5, 'x': 4, 'q': 3, 'z': 2,
    '.': 10, '0': 5, '1': 5, '2': 5, '3': 5, '4': 5, '5': 5, '6': 5, '7': 5, '8': 5, '9': 5
}

alphabet = " abcdefghijklmnopqrstuvwxyz0123456789."
heap = [[f, [c, ""]] for c, f in freqs.items()]
heapq.heapify(heap)
while len(heap) > 1:
    lo = heapq.heappop(heap)
    hi = heapq.heappop(heap)
    for pair in lo[1:]: pair[1] = '0' + pair[1]
    for pair in hi[1:]: pair[1] = '1' + pair[1]
    heapq.heappush(heap, [lo[0] + hi[0]] + lo[1:] + hi[1:])

codes_dict = {c: code for c, code in heap[0][1:]}

def make_canonical(codes_dict):
    items = sorted(codes_dict.items(), key=lambda x: (len(x[1]), x[0]))
    canonical = {}
    code = 0
    prev_len = len(items[0][1])
    for char, old_code in items:
        curr_len = len(old_code)
        code <<= (curr_len - prev_len)
        canonical[char] = format(code, f'0{curr_len}b')
        code += 1
        prev_len = curr_len
    return canonical

canonical = make_canonical(codes_dict)

# Map codes back to alphabet order
sorted_chars = list(alphabet)
codes_val = [int(canonical[c], 2) for c in sorted_chars]
lens_val = [len(canonical[c]) for c in sorted_chars]

print(f"codes := {codes_val}")
print(f"lens := {lens_val}")

items = sorted(canonical.items(), key=lambda x: (len(x[1]), x[0]))
syms = [ord(char) for char, code in items]
syms_str = ", ".join([f"u8(`{chr(s) if chr(s) != ' ' else ' '}`)" for s in syms])
print(f"syms := [{syms_str}]")

max_len = max(len(c) for c in canonical.values())
fc = [0] * (max_len + 1)
fo = [0] * (max_len + 1)
cn = [0] * (max_len + 1)

offset = 0
for l in range(1, max_len + 1):
    l_items = [x for x in items if len(x[1]) == l]
    if l_items:
        fc[l] = int(l_items[0][1], 2)
        fo[l] = offset
        cn[l] = len(l_items)
        offset += len(l_items)

print(f"fc := {fc}")
print(f"fo := {fo}")
print(f"cn := {cn}")
