### Triage benchmark — model `Qwen3-4B-Q5_K_M.gguf`

| config | recall (affected caught) | alert reduction | precision | accuracy | needs review | symbol hit | LLM calls | time (s) |
|---|---|---|---|---|---|---|---|---|
| scanner | 100% (12/12) | 0% (0/21) | 36% | 36% | 0% | - | 0 | 0 |
| reach-diff | 100% (12/12) | 10% (2/21) | 39% | 42% | 82% | 79% | 0 | 49 |
| reach-llm | 100% (12/12) | 10% (2/21) | 39% | 42% | 94% | 100% | 33 | 193 |
| workflow | 83% (10/12) | 81% (17/21) | 71% | 82% | 21% | 97% | 92 | 290 |
| agent | 83% (10/12) | 52% (11/21) | 50% | 64% | 18% | 97% | 209 | 492 |

### Retrieval — advisory text → vulnerable library symbol

| method | recall@5 | recall@10 | recall@20 |
|---|---|---|---|
| bm25 | 64% | 82% | 82% |
| dense | 91% | 100% | 100% |
| hybrid | 82% | 100% | 100% |

(n = 11 advisories)
