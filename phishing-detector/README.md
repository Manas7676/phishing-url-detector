# Phishing URL Detection System (NSC Mini-Project)
Front-end-only, heuristic-based educational prototype. **It is not a trained ML model**; every rule and weight is visible in `detector.js`. No URL is ever opened or fetched.

## Run on Windows
1. Extract the ZIP. 2. Double-click `index.html`.
Or use a local server: open Command Prompt in the folder, run `python -m http.server 8000`, then browse to http://localhost:8000.
No installation or `requirements.txt` is needed.

## Algorithm
Validate/normalize (browser `URL` parser) -> extract 13 features -> test 12 weighted rules -> sum weights (cap 100) -> classify: <25 Low Risk, 25-49 Suspicious, >=50 High Risk.
Weights: IP host 25, @ symbol 20, punycode 15, 3+ subdomains 15, no HTTPS 12, 2+ hyphens 10, long URL 10, odd port 10, keywords 8 each (max 24), long path 6, 4+ host digits 6, 3+ encoded chars 5.
The score is a heuristic estimate, not a probability. A Low Risk result is not a guarantee of safety.

## Sample tests (use the sample buttons)
| Sample | Expected |
|---|---|
| https://www.example.com/about | 0, Low Risk |
| http://example.com/secure-login/verify-account.php | 36, Suspicious |
| http://192.168.1.20/login/update | 53, High Risk (IP rule) |
| https://secure.login.account-verify.example.com/signin | 39, Suspicious |
| https://www.paypal.com@example.net/verify | 28, Suspicious (@ rule + keyword) |
| long combined sample | 77, High Risk |
| empty text / `http://` | Clear error at Stage 1 |

## Demo tips
Use **Step-by-Step** mode and press Next Step to explain each stage. Delay only affects animation speed, never results.

## Troubleshooting
- History not saving: some browsers block localStorage for `file://`; use the local server command.
- Blank page: ensure `detector.js`, `app.js`, `style.css` sit beside `index.html`.
