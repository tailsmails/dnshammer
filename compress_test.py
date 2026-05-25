import collections, heapq

def build_huffman_v_style(data):
    # Characters: ' ', a-z, 0-9, '.'
    alphabet = " abcdefghijklmnopqrstuvwxyz0123456789."
    # Fixed frequencies (approximate English + digits)
    freqs = {
        ' ': 150, 'e': 100, 't': 80, 'a': 75, 'o': 70, 'i': 65, 'n': 65, 's': 60, 'r': 60, 'h': 50,
        'l': 40, 'd': 35, 'c': 30, 'u': 28, 'm': 25, 'w': 22, 'f': 20, 'g': 18, 'y': 18, 'p': 16,
        'b': 14, 'v': 10, 'k': 7, 'j': 5, 'x': 4, 'q': 3, 'z': 2,
        '.': 10, '0': 5, '1': 5, '2': 5, '3': 5, '4': 5, '5': 5, '6': 5, '7': 5, '8': 5, '9': 5
    }

    heap = [[f, [c, ""]] for c, f in freqs.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        lo = heapq.heappop(heap)
        hi = heapq.heappop(heap)
        for pair in lo[1:]: pair[1] = '0' + pair[1]
        for pair in hi[1:]: pair[1] = '1' + pair[1]
        heapq.heappush(heap, [lo[0] + hi[0]] + lo[1:] + hi[1:])

    codes = sorted(heap[0][1:], key=lambda x: alphabet.index(x[0]))
    return codes

codes = build_huffman_v_style("")
for c, code in codes:
    print(f"'{c}': {len(code)} bits ({code})")

test_text = "hello my name is john. i am 25 years old."
total_bits = 0
for c in test_text.lower():
    if c in [x[0] for x in codes]:
        total_bits += len([x[1] for x in codes if x[0] == c][0])
print(f"Total bits: {total_bits}")
