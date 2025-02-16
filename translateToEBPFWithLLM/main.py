import subprocess
import requests # Import requests library

def call_gemini_api(iptables_rules, api_key, model_name="gemini-2.0-flash-thinking-exp-01-21"):
    """
    Calls the Google Gemini API to translate iptables rules to eBPF code.

    Args:
        iptables_rules (str): iptables rules in iptables-save format.
        api_key (str): Google Gemini API key.
        model_name (str): Gemini model name to use (default: gemini-2.0-flash-thinking-exp-01-21).

    Returns:
        str: Translated eBPF code as a string, or None in case of error.
    """
    api_endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
    params = {"key": api_key}
    headers = {"Content-Type": "application/json"}
    prompt_text = f"Translate the following iptables rules to eBPF code:\n\n{iptables_rules}"
    data = {
        "contents": [ # Update request body format to match Gemini API spec
            {
                "parts": [
                    {
                        "text": prompt_text
                    }
                ]
            }
        ]
    }

    try:
        response = requests.post(api_endpoint, params=params, headers=headers, json=data)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        api_response = response.json()
        # Extract eBPF code from API response - Robust extraction with error handling
        candidates = api_response.get("candidates")
        if not candidates:
            print("Error: No candidates found in Gemini API response.")
            return None
        content = candidates[0].get("content")
        if not content:
            print("Error: No content found in the first candidate.")
            return None
        parts = content.get("parts")
        if not parts:
            print("Error: No parts found in the content.")
            return None
        text_content = parts[0].get("text")
        if not text_content:
            print("Error: No text found in the first part.")
            return None
        ebpf_code = text_content.strip() # Extract eBPF code and strip whitespace
        print("Gemini API Response:") # Print full API response for debugging
        print(api_response) # Print full API response for debugging
        return ebpf_code
    except requests.exceptions.RequestException as e:
        print(f"Error calling Gemini API: {e}")
        return None

def main():
    api_key = "AIzaSyA979FQXSOj27Fe7Y7akNnxVbKgkehHYxc" # User provided API key
    model_name = "gemini-2.0-flash-thinking-exp-01-21" # User provided model name
    
    iptables_file_path = "translateToEBPFWithLLM/iptables-save" # User provided file path
    try:
        with open(iptables_file_path, "r") as f:
            iptables_rules = f.read()
    except FileNotFoundError:
        print(f"Error: iptables rules file not found at '{iptables_file_path}'")
        return


    ebpf_code = call_gemini_api(iptables_rules, api_key, model_name)

    if ebpf_code:
        print("Generated eBPF code:")
        print(ebpf_code)
        # Save eBPF code to file
        output_file_path = "output_ebpf_attempt_1.c"
        try:
            with open(output_file_path, "w") as f:
                f.write(ebpf_code)
            print(f"eBPF code saved to '{output_file_path}'")
        except Exception as e:
            print(f"Error saving eBPF code to file: {e}")
    else:
        print("Error translating to eBPF code.")

if __name__ == "__main__":
    main()
