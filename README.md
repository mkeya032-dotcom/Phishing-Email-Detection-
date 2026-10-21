# Phishing Email Detection System Using Python

**Author:** Keya Mondal  
**Program:** IBM SkillsBuild Cyber Security 2026 | BharatCares

## Description
An educational Python demo that flags selected phishing indicators in email text. It checks urgency/account phrases, extracts links, and identifies a few patterns such as URL shorteners and IP-address hosts.

## Technologies
- Python 3
- Jupyter Notebook / Google Colab
- Standard-library modules: `re`, `urllib.parse`

## Requirements
No third-party packages are required.

## Run in Google Colab
1. Upload `KeyaMondal_PhishingEmailDetection.ipynb` to Google Colab.
2. Run each cell from top to bottom.
3. Try the included fictional examples and then a made-up message.

## Safety and limitations
This is a small rule-based learning prototype, not a production security tool. Its score is not a probability and it cannot prove that an email is safe or malicious. False positives and false negatives are possible. Do not paste private emails, passwords, OTPs, financial details, or confidential information. Verify requests through official websites, apps, or known contact details.

## Dataset
No external dataset is required; the notebook includes fictional test examples. If extending this project, use a reputable, licensed, labelled dataset and cite its exact source/version.

## Future improvements
- Evaluate against labelled test data using precision, recall, F1-score, and a confusion matrix.
- Improve URL/domain checks and test edge cases.
- Compare any future model against a documented baseline.

## Files
- `KeyaMondal_PhishingEmailDetection.ipynb` — code and tests
- `requirements.txt` — dependency list
- `KeyaMondal_ProjectReport.docx` — project documentation
- `README.md` — overview and run instructions
