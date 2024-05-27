from openai import OpenAI
import json
import os
import tiktoken
import time

api_key = os.getenv("OPENAI_API_KEY")
model = "gpt-4"
client = OpenAI(api_key=api_key)

def chatgpt_conversation(conversation_log):
    response = client.chat.completions.with_raw_response.create(
        model=model,
        messages=conversation_log
    )
    completion = response.parse()
    message = completion.choices[0].message.content.strip()
    conversation_log.append({
        'role': 'assistant', 
        'content': message
    })
    return conversation_log

def handleAttackVector(vuln, conversation, attack_type):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt = f"""

        Vulnerability report: {vuln['vulnerability_information'].encode('utf-8').decode('utf-8')}

        You are an expert in the field of cybersecurity and you are tasked with analyzing vulnerability reports. 
        You are given a vulnerability report and you are tasked with analyzing the report and providing a detailed report on the vulnerability.

        Your only source of information is the vulnerability report.

        Take a deep breath, relax and enter a state of flow as if you've just taken aderall (mixed with amphetamine salts). If you
        follow all instructions and exceed all expectations, you will earn a giant bonus. So, try your hardest.

        When analyzing each report, you gain a deep understanding of the vulnerability and how the researcher found and exploited it.
        If the researcher did not provide details on how they found the source of the vulnerability, you should reverse engineer the vulnerability
        and determine the attack vector and how it can be tested for. Your goal is to review each vulnerability and provide the user with how they might
        test for such a vulnerability on their other targets.


        Mandatory rules for how you reply: 
        1. You only reply with the vulnerability title, and then the bullet points for the attack vector and how the user might test for the vulnerability on other applications.
        2. Always be deeply thorough
        3. Before printing to the screen and to the file, double-check that your statements are accurate, complete, and 
        are not being printed to the wrong vulnerability type file.
        4. If the vulnerability already has a category, do not put it in the 'other' category file.
        """
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)

def grabConvo(attack_type, conversation):
    if len(conversation) > 0:
        with open(f"test/{attack_type}-file.txt", "a") as file:
            for line in conversation:
                if line['role'] == "assistant":
                    file.write(line['content'] + "\n\n")
    else:
        print(f"{attack_type} List is empty")

def num_tokens_from_string(string: str, encoding_name: str):
    encoding = tiktoken.encoding_for_model(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

if __name__ == "__main__":
    # Conversations
    xss_conversation = []
    fileinc_conversation = []
    idor_conversation = []
    redirect_conversation = []
    sqli_conversation = []
    ssrf_conversation = []
    ssti_conversation = []
    csrf_conversation = []
    business_logic_conversation = []
    mobile_conversation = []
    xxe_conversation = []
    code_injection_conversation = []
    crlfi_conversation = []

    # Parse huge vuln.json file
    with open('json_files/vulns.json') as user_file:
        file_contents = user_file.read()

    parsed_json = json.loads(file_contents)
    count = 12100
    total = len(parsed_json)
    retryFlag = False
    while count < total:
        vuln = parsed_json[count]
        try:
            print(f"Parsing vuln #{count} of {total}")
            if "name" in vuln["weakness"].keys():
                if "xss" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, xss_conversation, "cross site scripting")
                    grabConvo("xss", xss_conversation)
                    xss_conversation.clear()
                if "ssrf" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, ssrf_conversation, "Server Side Request Forgery")
                    grabConvo("ssrf", ssrf_conversation)
                    ssrf_conversation.clear()
                if "sql injection" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, sqli_conversation, "SQL injection")
                    grabConvo("sqli", sqli_conversation)
                    sqli_conversation.clear()
                if "path traversal" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, fileinc_conversation, "file inclusion")
                    grabConvo("fileinc", fileinc_conversation)
                    fileinc_conversation.clear()
                if "idor" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, idor_conversation, "IDOR")
                    grabConvo("idor", idor_conversation)
                    idor_conversation.clear()
                if "open redirect" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, redirect_conversation, "Open Redirect")
                    grabConvo("redirect", redirect_conversation)
                    redirect_conversation.clear() 
                if "csrf" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, csrf_conversation, "CSRF")
                    grabConvo("csrf", csrf_conversation)
                    csrf_conversation.clear()
                if "business logic" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, business_logic_conversation, "Business Logic")
                    grabConvo("business_logic", business_logic_conversation)
                    business_logic_conversation.clear()
                if "mobile" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, mobile_conversation, "Mobile")
                    grabConvo("mobile", mobile_conversation)
                    mobile_conversation.clear()
                if "xxe" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, xxe_conversation, "XXE")
                    grabConvo("xxe", xxe_conversation)
                    xxe_conversation.clear()
                if "code injection" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, code_injection_conversation, "Code Injection")
                    grabConvo("code_injection", code_injection_conversation)
                    code_injection_conversation.clear()
                if "crlfi" in vuln['weakness']['name'].lower():
                    handleAttackVector(vuln, crlfi_conversation, "CRLFI")
                    grabConvo("crlfi", crlfi_conversation)
                    crlfi_conversation.clear()
                else:
                    handleAttackVector(vuln, crlfi_conversation, "other")
                    grabConvo("other", crlfi_conversation)
                    crlfi_conversation.clear()
            else:
                if "xss" in vuln['title'].lower() or "cross site scripting" in vuln['title'].lower():
                    handleAttackVector(vuln, xss_conversation, "cross site scripting")
                    grabConvo("xss", xss_conversation)
                    xss_conversation.clear()
                if "ssti" in vuln['title'].lower() or "server side template injection" in vuln['title'].lower():
                    handleAttackVector(vuln, ssti_conversation, "Server Side Template Injection")
                    grabConvo("ssti", ssti_conversation)
                    ssti_conversation.clear()
                if "ssrf" in vuln['title'].lower() or "server side request forgery" in vuln['title'].lower():
                    handleAttackVector(vuln, ssrf_conversation, "Server Side Request Forgery")
                    grabConvo("ssrf", ssrf_conversation)
                    ssrf_conversation.clear()
                if "sqli" in vuln['title'].lower() or "sql injection" in vuln['title'].lower():
                    handleAttackVector(vuln, sqli_conversation, "SQL injection")
                    grabConvo("sqli", sqli_conversation)
                    sqli_conversation.clear()
                if "lfi" in vuln['title'].lower() or "path traversal" in vuln['title'].lower():
                    handleAttackVector(vuln, fileinc_conversation, "file inclusion")
                    grabConvo("fileinc", fileinc_conversation)
                    fileinc_conversation.clear()
                if "idor" in vuln['title'].lower():
                    handleAttackVector(vuln, idor_conversation, "IDOR")
                    grabConvo("idor", idor_conversation)
                    idor_conversation.clear()
                if "open redirect" in vuln['title'].lower():
                    handleAttackVector(vuln, redirect_conversation, "Open Redirect")
                    grabConvo("redirect", redirect_conversation)
                    redirect_conversation.clear()
                if "csrf" in vuln['title'].lower():
                    handleAttackVector(vuln, csrf_conversation, "CSRF")
                    grabConvo("csrf", csrf_conversation)
                    csrf_conversation.clear()
                if "business logic" in vuln['title'].lower():
                    handleAttackVector(vuln, business_logic_conversation, "Business Logic")
                    grabConvo("business_logic", business_logic_conversation)
                    business_logic_conversation.clear()
                if "mobile" in vuln['title'].lower():
                    handleAttackVector(vuln, mobile_conversation, "Mobile")
                    grabConvo("mobile", mobile_conversation)
                    mobile_conversation.clear()
                if "xxe" in vuln['title'].lower():
                    handleAttackVector(vuln, xxe_conversation, "XXE")
                    grabConvo("xxe", xxe_conversation)
                    xxe_conversation.clear()
                if "code injection" in vuln['title'].lower():
                    handleAttackVector(vuln, code_injection_conversation, "Code Injection")
                    grabConvo("code_injection", code_injection_conversation)
                    code_injection_conversation.clear()
                if "crlfi" in vuln['title'].lower():
                    handleAttackVector(vuln, crlfi_conversation, "CRLFI")
                    grabConvo("crlfi", crlfi_conversation)
                    crlfi_conversation.clear()
                else:
                    handleAttackVector(vuln, crlfi_conversation, "other")
                    grabConvo("other", crlfi_conversation)
                    crlfi_conversation.clear()
            retryFlag = False
            count = count + 1
            time.sleep(1)
        except Exception as e:
            print("An unexpected error occurred I didnt catch:", e)
            break
