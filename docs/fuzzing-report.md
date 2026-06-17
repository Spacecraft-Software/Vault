<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# EncString Fuzzing Report

**Target:** `vault-core::EncString::parse` (Bitwarden type 2 ciphertext parser)  
**Harness:** `fuzz/fuzz_targets/enc_string_parse.rs`  
**Date:** 2026-06-18  
**Duration:** 86,401 seconds (24 hours)  
**Toolchain:** nightly-x86_64-unknown-linux-gnu via rustup

## Objective

PRD §11.4 requires a ≥24-hour fuzz soak of the `EncString` parser with no findings before the v0.1.0 tag. The parser base64-decodes attacker-influenceable cache and `/sync` responses into IV/ciphertext/MAC — it must never panic and must maintain parse→serialize→parse round-trip consistency.

## Configuration

| Parameter | Value |
|-----------|-------|
| Fuzzer | libFuzzer (via `cargo-fuzz`) |
| Target | `enc_string_parse` |
| Time limit | 86,400 seconds |
| Corpus seed | 436 files, 87,318 bytes |
| Max input length | 4,096 bytes |

## Raw terminal output

The following is the complete console output from the fuzz run, captured verbatim:

```
warning: linker stderr: lto-wrapper: using serial compilation of 5 LTRANS jobs
         lto-wrapper: note: see the '-flto' option documentation for more information
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `vault-fuzz` (bin "enc_string_parse") generated 1 warning
    Finished `release` profile [optimized + debuginfo] target(s) in 0.08s
warning: linker stderr: lto-wrapper: using serial compilation of 5 LTRANS jobs
         lto-wrapper: note: see the '-flto' option documentation for more information
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `vault-fuzz` (bin "enc_string_parse") generated 1 warning
    Finished `release` profile [optimized + debuginfo] target(s) in 0.05s
     Running `target/x86_64-unknown-linux-gnu/release/enc_string_parse -artifact_prefix=/spacecraft-software/vault/fuzz/artifacts/enc_string_parse/ -max_total_time=86400 /spacecraft-software/vault/fuzz/corpus/enc_string_parse`
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1512457441
INFO: Loaded 1 modules   (25059 inline 8-bit counters): 25059 [0x5af8ba353868, 0x5af8ba359a4b), 
INFO: Loaded 1 PC tables (25059 PCs): 25059 [0x5af8ba359a50,0x5af8ba3bb880), 
INFO:      436 files found in /spacecraft-software/vault/fuzz/corpus/enc_string_parse
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: seed corpus: files: 436 min: 1b max: 4096b total: 87318b rss: 34Mb
#437	INITED cov: 312 ft: 922 corp: 133/27Kb exec/s: 0 rss: 43Mb
#262144	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 131072 rss: 406Mb
#524288	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 104857 rss: 413Mb
#899176	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 99908 rss: 413Mb L: 22/4096 MS: 4 EraseBytes-ShuffleBytes-ChangeBit-ChangeByte-
#1048576	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 104857 rss: 413Mb
#1224963	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 102080 rss: 413Mb L: 523/4096 MS: 2 ChangeBit-EraseBytes-
#1570019	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 98126 rss: 414Mb L: 73/4096 MS: 1 EraseBytes-
#2097152	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 99864 rss: 414Mb
#2301700	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 100073 rss: 414Mb L: 267/4096 MS: 1 EraseBytes-
#2808286	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 104010 rss: 415Mb L: 244/4096 MS: 1 EraseBytes-
#3617097	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 103345 rss: 419Mb L: 57/4096 MS: 1 EraseBytes-
#4194304	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 99864 rss: 419Mb
#5068411	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 97469 rss: 419Mb L: 30/4096 MS: 4 ChangeBinInt-EraseBytes-ShuffleBytes-ChangeBit-
#5290457	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 97971 rss: 419Mb L: 265/4096 MS: 1 EraseBytes-
#6232498	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 97382 rss: 419Mb L: 119/4096 MS: 1 EraseBytes-
#6914709	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 96037 rss: 419Mb L: 62/4096 MS: 1 EraseBytes-
#7247071	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 95356 rss: 419Mb L: 248/4096 MS: 2 InsertRepeatedBytes-EraseBytes-
#7382042	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 95870 rss: 419Mb L: 264/4096 MS: 1 EraseBytes-
#8388608	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 94254 rss: 420Mb
#9265633	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 93592 rss: 420Mb L: 117/4096 MS: 1 EraseBytes-
#9305383	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 93053 rss: 420Mb L: 54/4096 MS: 5 InsertByte-ChangeASCIIInt-CrossOver-ChangeBinInt-EraseBytes-
#10092809	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 92594 rss: 420Mb L: 264/4096 MS: 1 EraseBytes-
#10216505	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 92040 rss: 420Mb L: 53/4096 MS: 1 EraseBytes-
#12333662	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 87472 rss: 422Mb L: 92/4096 MS: 2 CrossOver-EraseBytes-
#12688693	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 86908 rss: 422Mb L: 91/4096 MS: 1 EraseBytes-
#13732260	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 84767 rss: 422Mb L: 263/4096 MS: 1 EraseBytes-
#16777216	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79512 rss: 425Mb
#17788491	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79769 rss: 426Mb L: 277/4096 MS: 1 EraseBytes-
#18432467	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 80141 rss: 427Mb L: 247/4096 MS: 1 EraseBytes-
#19473118	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79807 rss: 427Mb L: 126/4096 MS: 1 EraseBytes-
#20451384	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79888 rss: 427Mb L: 243/4096 MS: 1 EraseBytes-
#20753240	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79514 rss: 427Mb L: 256/4096 MS: 1 EraseBytes-
#21375630	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79463 rss: 428Mb L: 56/4096 MS: 5 ShuffleBytes-InsertRepeatedBytes-ChangeBinInt-ChangeBinInt-EraseBytes-
#22480216	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79435 rss: 429Mb L: 522/4096 MS: 1 EraseBytes-
#22801457	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79447 rss: 429Mb L: 255/4096 MS: 1 EraseBytes-
#23793180	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 79575 rss: 431Mb L: 116/4096 MS: 3 ChangeBinInt-ShuffleBytes-EraseBytes-
#28707647	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 78651 rss: 432Mb L: 251/4096 MS: 2 ChangeBinInt-EraseBytes-
#28832244	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 78561 rss: 432Mb L: 274/4096 MS: 2 ChangeBit-EraseBytes-
#29159670	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 78386 rss: 432Mb L: 263/4096 MS: 1 EraseBytes-
#29200511	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 78495 rss: 432Mb L: 122/4096 MS: 1 EraseBytes-
#30042267	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 78235 rss: 432Mb L: 250/4096 MS: 1 EraseBytes-
#31280668	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 77812 rss: 432Mb L: 90/4096 MS: 1 EraseBytes-
#33116731	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 77375 rss: 432Mb L: 134/4096 MS: 3 ChangeByte-EraseBytes-CopyPart-
#33470954	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 77300 rss: 432Mb L: 16/4096 MS: 3 ChangeASCIIInt-EraseBytes-CMP- DE: "\377\377\377\377"-
#33554432	pulse  cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 77314 rss: 433Mb
#41375995	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 74150 rss: 437Mb L: 273/4096 MS: 1 EraseBytes-
#42057332	REDUCE cov: 312 ft: 922 corp: 133/27Kb lim: 4096 exec/s: 74175 rss: 437Mb L: 133/4096 MS: 2 EraseBytes-ChangeByte-
#47008223	NEW    cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 74262 rss: 440Mb L: 4096/4096 MS: 1 CrossOver-
#47127135	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 74333 rss: 440Mb L: 261/4096 MS: 2 CopyPart-EraseBytes-
#52955135	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 76746 rss: 452Mb L: 61/4096 MS: 5 CrossOver-ChangeBit-CrossOver-ShuffleBytes-EraseBytes-
#53143626	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 76797 rss: 452Mb L: 241/4096 MS: 1 EraseBytes-
#56801897	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 78131 rss: 453Mb L: 114/4096 MS: 1 EraseBytes-
#61522007	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 79691 rss: 453Mb L: 22/4096 MS: 5 ChangeBit-ChangeBinInt-EraseBytes-ChangeByte-PersAutoDict- DE: "\377\377\377\377"-
#67108864	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 80854 rss: 455Mb
#73292123	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 83097 rss: 455Mb L: 245/4096 MS: 1 EraseBytes-
#81244415	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 85520 rss: 455Mb L: 27/4096 MS: 2 CMP-EraseBytes- DE: "\377\377\377\377"-
#88536641	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 87228 rss: 455Mb L: 262/4096 MS: 1 EraseBytes-
#95243309	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88433 rss: 455Mb L: 260/4096 MS: 3 PersAutoDict-EraseBytes-CopyPart- DE: "\377\377\377\377"-
#97018670	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88763 rss: 455Mb L: 259/4096 MS: 1 EraseBytes-
#103050447	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89765 rss: 455Mb L: 118/4096 MS: 1 EraseBytes-
#120719260	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89887 rss: 455Mb L: 31/4096 MS: 3 ChangeByte-ChangeBinInt-EraseBytes-
#126401432	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89329 rss: 455Mb L: 60/4096 MS: 2 EraseBytes-PersAutoDict- DE: "\377\377\377\377"-
#134217728	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88127 rss: 455Mb
#162270068	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 87618 rss: 455Mb L: 249/4096 MS: 1 EraseBytes-
#178765585	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 87931 rss: 455Mb L: 521/4096 MS: 2 ChangeBit-EraseBytes-
#197276586	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89875 rss: 455Mb L: 132/4096 MS: 1 EraseBytes-
#206503373	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 90531 rss: 455Mb L: 261/4096 MS: 2 EraseBytes-ChangeByte-
#250340520	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89759 rss: 456Mb L: 46/4096 MS: 2 InsertRepeatedBytes-EraseBytes-
#253702036	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89584 rss: 456Mb L: 260/4096 MS: 1 EraseBytes-
#268435456	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88797 rss: 456Mb
#324040958	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88222 rss: 456Mb L: 254/4096 MS: 2 ChangeBinInt-EraseBytes-
#332618555	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88297 rss: 456Mb L: 253/4096 MS: 2 ChangeByte-EraseBytes-
#385563602	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 87172 rss: 457Mb L: 1045/4096 MS: 1 EraseBytes-
#398614518	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 87243 rss: 457Mb L: 252/4096 MS: 1 EraseBytes-
#423420080	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 87375 rss: 457Mb L: 125/4096 MS: 2 InsertByte-EraseBytes-
#465467148	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 88006 rss: 457Mb L: 520/4096 MS: 3 EraseBytes-ShuffleBytes-ShuffleBytes-
#520354749	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89025 rss: 457Mb L: 4095/4096 MS: 1 EraseBytes-
#536870912	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 89523 rss: 458Mb
#624273755	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 91872 rss: 458Mb L: 519/4096 MS: 1 EraseBytes-
#625331238	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 91906 rss: 458Mb L: 518/4096 MS: 3 CopyPart-CopyPart-EraseBytes-
#701762246	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 93780 rss: 458Mb L: 517/4096 MS: 2 ShuffleBytes-EraseBytes-
#724188235	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 94295 rss: 458Mb L: 247/4096 MS: 3 CrossOver-ChangeASCIIInt-EraseBytes-
#882267731	REDUCE cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 97326 rss: 458Mb L: 246/4096 MS: 1 EraseBytes-
#1073741824	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 99651 rss: 458Mb
#2147483648	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 104980 rss: 459Mb
#4294967296	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 104370 rss: 459Mb
#8589934592	pulse  cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 103442 rss: 459Mb
#8874210317	DONE   cov: 312 ft: 928 corp: 134/31Kb lim: 4096 exec/s: 102709 rss: 459Mb
###### Recommended dictionary. ######
"\377\377\377\377" # Uses: 801644167
###### End of recommended dictionary. ######
Done 8874210317 runs in 86401 second(s)
```

## Results summary

| Metric | Value |
|--------|-------|
| Total executions | 8,874,210,317 (~8.9 billion) |
| Execution rate | ~102,709 exec/s |
| Coverage (hit blocks) | 312 |
| Features (`ft:`) | 928 |
| Final corpus size | 134 files, 31 KB |
| Peak RSS | 459 MB |
| Findings (artifacts) | **0** |
| Exit code | 0 |

## Post-run verification

```sh
$ ls -la fuzz/artifacts/enc_string_parse/
total 8
drwxr-xr-x 2 mj users 4096 Jun 16 10:19 .
drwxr-xr-x 2 mj users 4096 Jun 16 10:19 ..
```

Confirmed: **No artifacts produced.** The directory contains only `.` and `..` — zero crash reproducers, zero findings.

## Conclusion

PRD §11.4 / RELEASING.md gate #1: **PASSED.** The EncString parser is stable and correct under 8.9 billion adversarial executions across 24 hours.

---

*Generated from the 24-hour soak run on 2026-06-18.*
