from rules import detect_sqli, detect_xss, detect_traversal, detect_command_injection

print(
detect_sqli("' OR '1'='1") ,                     # expect True
detect_xss("<script>alert(1)</script>"),         # expect True
detect_traversal("../../etc/passwd"),             # expect True
detect_command_injection("; whoami"),              # expect True
detect_sqli("laptop"),            # expect False
detect_xss("John O'Brien"),       # expect False — apostrophes in real names are a classic false-positive trap
detect_traversal("my-file.txt"),  # expect False
detect_command_injection("hello world")  # expect False


)