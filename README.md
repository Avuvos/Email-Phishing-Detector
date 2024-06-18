# Email Phishing Detector

This Python script is designed to detect potential phishing emails by analyzing the email content based on three key indicators:
1. Presence of urgent and manipulative words.
2. URLs that may be suspicious.
3. Sender's email address, particularly the domain part, to identify spoofing attempts.

## How Does It work?

- **Urgent Words Detection**: Scans the email for words that imply urgency or deception, which are commonly used in phishing attempts.
- **Suspicious URLs Detection**: Checks for URLs within the email that could be potentially harmful or deceptive.  
    It uses the `VirusTotal API` to validate URLs against known malicious sites.
- **Sender Address Verification**: Utilizes edit distance technique (implemented via dynamic programming) to determine if the domain of the sender's address is trying to mimic a trusted domain.

## Test Examples
There are two sample tests provided:

### Test 1
**Email Data**:   
``` 
security@gooogle.com  
Dear User,  
Your account has been compromised.  
Act immediately to secure your account.  
Visit http://192.168.1.1/reset to reset your password.  
Best Regards,  
Security Team.  
```
**Output**:
```
Email might be dangerous due to the following reasons:

Notice that the sender domain is gooogle.com
which is very similar to google.com
but not exactly!

Notice some suspicious urls were found:
	url = http://192.168.1.1/reset contains ip address

Notice some suspicious urgent words were found:
	Act
	immediately
```

### Test 2
**Email Data**:
``` 
admin@paypall.com
Dear Customer,
Please review your invoice and proceed with the payment within the next 24 hours.
Visit our website and follow the necessary steps.
Payment link for your convenience: http://myetherevvalliet.com/
Thank you,
Paypal's administration team.
```

**Output**:
```
Email might be dangerous due to the following reasons:

Notice that the sender domain is paypall.com
which is very similar to paypal.com
but not exactly!

Notice some suspicious urls were found:
	url = http://myetherevvalliet.com/ got 16 malicious votes

Notice some suspicious urgent words were found:
	invoice
```
## Usage

You need to give the script a file that has the email data.  
The file should look like this:  
- First line: Sender's email address.
- Remaining lines: Email content.

### VirusTotal
To use the URL validation feature, you need to provide your `VirusTotal API` key in a file named `secret.txt`.  
If the API key is not provided, the script will still run but will skip the URL validation step.
