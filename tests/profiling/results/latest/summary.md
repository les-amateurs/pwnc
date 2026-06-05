# pwnc startup profile

- generated_at: 2026-05-16T02:16:11.086851+00:00
- command: `./bin/pwnc --help`
- iterations: 20
- min: 79.39 ms
- mean: 83.53 ms
- median: 82.80 ms
- p90: 86.07 ms
- max: 91.23 ms
- stdev: 3.11 ms

## Slowest imports by cumulative time

| cumulative | self | module |
| ---: | ---: | --- |
| 25.479 ms | 0.246 ms | `pwnc` |
| 15.880 ms | 0.314 ms | `argcomplete` |
| 13.142 ms | 0.256 ms | `pwnc.util` |
| 11.984 ms | 0.557 ms | `pwnc.minelf` |
| 10.823 ms | 0.292 ms | `argcomplete.completers` |
| 8.442 ms | 1.183 ms | `site` |
| 7.995 ms | 0.194 ms | `pwnc.err` |
| 6.268 ms | 2.057 ms | `logging` |
| 5.380 ms | 1.071 ms | `argparse` |
| 5.151 ms | 0.792 ms | `subprocess` |

## Slowest imports by self time

| self | cumulative | module |
| ---: | ---: | --- |
| 2.686 ms | 2.737 ms | `typing` |
| 2.262 ms | 2.262 ms | `_hashlib` |
| 2.057 ms | 6.268 ms | `logging` |
| 1.798 ms | 1.901 ms | `locale` |
| 1.640 ms | 4.149 ms | `shutil` |
| 1.577 ms | 1.577 ms | `ipaddress` |
| 1.379 ms | 1.379 ms | `enum` |
| 1.183 ms | 8.442 ms | `site` |
| 1.173 ms | 2.877 ms | `urllib.parse` |
| 1.090 ms | 1.611 ms | `lzma` |
