#!/usr/bin/env bash
# Start the local model servers used by vigil.
#   chat  : :8080  (OpenAI-compatible, tool calling via jinja templates)
#   embed : :8081  (nomic-embed-text, CPU — leaves VRAM for the chat model)
set -euo pipefail
LLAMA="${LLAMA_CPP:-$HOME/llama.cpp/build/bin}"
MODELS="${MODELS_DIR:-$HOME/models/llama.cpp}"
CHAT_MODEL="${VIGIL_CHAT_MODEL:-$MODELS/Qwen3-4B-Q5_K_M.gguf}"
EMBED_MODEL="${VIGIL_EMBED_MODEL:-$MODELS/nomic-embed-text-v1.5.Q8_0.gguf}"
mkdir -p .vigil/logs

"$LLAMA/llama-server" -m "$CHAT_MODEL" --port 8080 -ngl 99 -c 16384 -fa on --jinja -np 1 \
  > .vigil/logs/chat.log 2>&1 &
echo "chat  pid $! ($CHAT_MODEL)"
"$LLAMA/llama-server" -m "$EMBED_MODEL" --port 8081 -ngl 0 --embedding --pooling mean -c 2048 -ub 2048 \
  > .vigil/logs/embed.log 2>&1 &
echo "embed pid $!"

for port in 8080 8081; do
  until curl -sf "localhost:$port/health" >/dev/null; do sleep 1; done
done
echo "servers ready"
