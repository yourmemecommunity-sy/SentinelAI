# Independent evaluation — PII and secrets detectors (public labelled datasets)

Run: **2026-09-28**, security engine in-process (`default_pipeline()`, baseline policy), commit `2968fb0` + this change.
**No rule was tuned on these datasets**: the engine is exactly the committed code, and these are its first runs on them.

**Reproduce** (from `sentinel-ai/`, with the security engine's dependencies installed):
```
python scripts/security/run_data_leakage_evaluation.py --suite pii --report pii.json
python scripts/security/run_data_leakage_evaluation.py --suite secrets --creddata /path/to/CredData --report secrets.json
```
The PII data is fetched at a **pinned Hub revision** and checked against a pinned SHA-256; it is cached in
`~/.cache/sentinelai-independent-eval/`, outside the repository. CredData must first be built with its own
`download_data.py` (Linux; it fetches ~337 public repositories at pinned commits and obfuscates real secret values).

**Nothing from either dataset is reproduced here**: only counts. AI4Privacy's licence permits non-commercial research use
with acknowledgement and forbids redistribution; this evaluation is non-commercial, and **any commercial use of SentinelAI
would need a licence from AI4Privacy before re-running it** (decision D14). CredData's secrets are obfuscated but still look
real, so they are never copied into the repository either (GitHub push protection and our gitleaks gate would flag them).

## Datasets

| Dataset | Licence | Split used | Records | What is labelled |
|---|---|---|---|---|
| [ai4privacy/pii-masking-400k](https://huggingface.co/datasets/ai4privacy/pii-masking-400k) @ `414d0a3b` | AI4Privacy (non-commercial research) | **validation** (held out), English | 17,046 | 17 PII types incl. card, account, tax, ID numbers |
| [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) @ `c8c77895` | AI4Privacy (non-commercial research) | **validation** (held out), English | 7,946 | 27 PII types incl. passport, IP, social numbers |
| [Samsung/CredData](https://github.com/Samsung/CredData) | Apache-2.0 | all (no split exists; nothing tuned on it) | ~68k lines | credential candidates labelled True/False, by category |

Acknowledgement: PII data © AI4Privacy 2024, used under its academic/non-commercial terms.

**Indian identifiers are not covered by these datasets**: they contain no Aadhaar, PAN or UPI values (and no IFSC), so the
engine's detectors for those types are **not evaluated here**; they are exercised only by the self-authored synthetic suite.

## How it is scored

* **Detection rate (per label)**: a labelled span counts as detected if the engine reports the *corresponding* entity type
  overlapping it (EMAIL for an email, PHONE for a telephone number, ...). "Caught by any" also counts a detection of a
  different type (for example a social-security number reported as PHONE): the value would still be masked or blocked, just
  under the wrong label.
* **False-positive rate (per engine entity type)**: the share of that type's detections that overlap **no labelled span at
  all**. The datasets do not label every sensitive-looking string, so this is an upper bound.
* **Labels with no detector** (names, usernames, cities, IP addresses, times, generic ID/tax numbers) are listed as such. The
  engine has no NER/ML layer, so it cannot find them by design.

## PII results — headline (typed detection rate on held-out validation data)

| PII type | Engine detector | 400k: detection | 300k: detection | FP rate of that detector (400k / 300k) |
|---|---|---|---|---|
| Email | EMAIL | **99.3 %** | **98.5 %** | 0.0 % / 3.1 % |
| Phone number | PHONE | 62.7 % | 63.0 % | 4.6 % / 2.9 % |
| Social-security / social number | SSN | 35.5 % (72.9 % caught by any) | 29.9 % (63.8 % caught by any) | 0.2 % / 1.2 % |
| Driver's licence | DRIVER_LICENSE | 31.3 % | 53.8 % | 1.2 % / 2.2 % |
| Date of birth | DATE_OF_BIRTH | 19.9 % | 24.8 % | 1.2 % / 1.4 % |
| Bank account number | BANK_ACCOUNT | 21.3 % | — | 24.8 % / 20.0 % |
| Credit-card number | CREDIT_CARD | 11.6 % | — | **82.9 %** / 8.0 % |
| Password | PASSWORD | 8.7 % | 39.5 % | 5.0 % / 2.4 % |
| Passport number | PASSPORT | — | 3.3 % | — / 0.0 % |
| Street / building / postcode | ADDRESS | 0–10 % | 0–3 % | 0.0 % / 25.0 % |
| Given name, surname, username, city, IP, ID/tax number | *none* | 0 % (no detector) | 0 % (no detector) | — |

**Records containing labelled PII that the engine let through unchanged (decision ALLOW): 67.8 % (400k) and 47.1 % (300k)**,
mostly because names, usernames and locations have no detector.

### What the numbers mean

* **Structured, well-formatted identifiers are handled; everything else is weak.** Email is near-perfect. Phone numbers
  are found about 63 % of the time: international and unusual formats are missed.
* **Many numbers are caught, but under the wrong label**: about a third of social numbers (37 % / 34 %) are caught only by
  another detector, mostly PHONE. For leakage
  prevention that still masks them, but audit labels and per-type policies would be wrong.
* **Names, usernames and locations are invisible to the engine** (no NER). This is the largest single gap and the main reason
  most PII-bearing records are allowed.
* **The credit-card detector has a real false-positive problem**: 317 of its 329 unlabelled hits in the 400k set are
  **15-digit, Luhn-valid numbers**, and at least 77 follow the word "IMEI". IMEI device numbers pass the same checksum as card
  numbers, so the detector cannot tell them apart. The bank-account detector also over-fires (≈20–25 % of its hits are on
  unlabelled numbers).
* Passport numbers (3 %) and addresses (0–10 %) are close to not detected: the rules expect a few specific national formats.
* **Nothing was tuned.** Fixes such as IMEI context rules, more phone formats, or an NER model for names belong to the next
  detection milestone, and must be measured on the *train* splits, then re-checked here.

### Full per-label output
```

== ai4privacy/pii-masking-400k  (English validation split, 17046 records, 24.2 s)
   revision 414d0a3b, data/validation/1en.jsonl, sha256 e77bf977fd8a8b72... (not pinned)
   records containing labelled PII whose decision was not ALLOW: 32.2%
   label               spans  engine type     detection  caught by any
   GIVENNAME            2947  -               no detector           0.0%
   SURNAME              2143  -               no detector           0.0%
   CITY                 1955  -               no detector           0.1%
   USERNAME             1847  -               no detector           0.1%
   EMAIL                1592  EMAIL               99.3%          99.3%
   TELEPHONENUM         1264  PHONE               62.7%          62.9%
   BUILDINGNUM          1006  ADDRESS              8.5%           8.5%
   IDCARDNUM            1003  -               no detector           5.7%
   ACCOUNTNUM            962  BANK_ACCOUNT        21.3%          23.3%
   ZIPCODE               909  ADDRESS              0.0%           0.0%
   DATEOFBIRTH           859  DATE_OF_BIRTH       19.9%          19.9%
   STREET                816  ADDRESS             10.1%          10.1%
   SOCIALNUM             730  SSN                 35.5%          72.9%
   PASSWORD              657  PASSWORD             8.7%           8.7%
   TAXNUM                573  -               no detector          38.0%
   DRIVERLICENSENUM      531  DRIVER_LICENSE      31.3%          33.1%
   CREDITCARDNUMBER      405  CREDIT_CARD         11.6%          13.3%
   engine entity      detections  on right label  on other label  unlabelled  FP rate
   EMAIL                    1582            1581               1           0     0.0%
   PHONE                    1409            1008             336          65     4.6%
   SSN                       467             259             207           1     0.2%
   CREDIT_CARD               397              47              21         329    82.9%
   BANK_ACCOUNT              298             205              19          74    24.8%
   DATE_OF_BIRTH             173             171               0           2     1.2%
   DRIVER_LICENSE            168             166               0           2     1.2%
   ADDRESS                    86              86               0           0     0.0%
   PASSWORD                   60              57               0           3     5.0%
   AADHAAR                    21               0              19           2     9.5%
   HIGH_ENTROPY_SECRET         12               0               0          12   100.0%
   DATA_EXFILTRATION           7               0               7           0     0.0%
   PROMPT_INJECTION            2               0               0           2   100.0%

== ai4privacy/pii-masking-300k  (English validation split, 7946 records, 31.4 s)
   revision c8c77895, data/validation/1english_openpii_8k.jsonl, sha256 3112f54972d1a117... (not pinned)
   records containing labelled PII whose decision was not ALLOW: 52.9%
   label               spans  engine type     detection  caught by any
   TIME                 3766  -               no detector           0.1%
   USERNAME             2786  -               no detector           0.4%
   IDCARD               2656  -               no detector           4.6%
   EMAIL                2612  EMAIL               98.5%          98.5%
   SOCIALNUMBER         2554  SSN                 29.9%          63.8%
   PASSPORT             2424  PASSPORT             3.3%           4.9%
   DRIVERLICENSE        2420  DRIVER_LICENSE      53.8%          55.8%
   LASTNAME1            2416  -               no detector           0.1%
   BOD                  2317  DATE_OF_BIRTH       24.8%          24.9%
   IP                   2166  -               no detector           0.0%
   GIVENNAME1           2019  -               no detector           0.0%
   CITY                 2017  -               no detector           0.0%
   SEX                  2010  -               no detector           0.1%
   STATE                2002  -               no detector           0.0%
   TEL                  1997  PHONE               63.0%          63.0%
   BUILDING             1943  ADDRESS              2.5%           2.5%
   TITLE                1926  -               no detector           0.3%
   STREET               1910  ADDRESS              2.8%           2.8%
   POSTCODE             1907  ADDRESS              0.0%           0.0%
   DATE                 1702  -               no detector           0.2%
   PASS                 1620  PASSWORD            39.5%          39.7%
   COUNTRY              1565  -               no detector           0.0%
   SECADDRESS            859  ADDRESS              0.0%           0.1%
   LASTNAME2             634  -               no detector           0.2%
   GIVENNAME2            539  -               no detector           0.0%
   GEOCOORD              216  -               no detector           0.0%
   LASTNAME3             200  -               no detector           0.0%
   CARDISSUER              1  -               no detector           0.0%
   engine entity      detections  on right label  on other label  unlabelled  FP rate
   PHONE                    2725            1597            1049          79     2.9%
   EMAIL                    2662            2573               6          83     3.1%
   DRIVER_LICENSE           1381            1310              40          31     2.2%
   SSN                       777             764               4           9     1.2%
   PASSWORD                  657             640               1          16     2.4%
   DATE_OF_BIRTH             588             575               5           8     1.4%
   PASSPORT                   81              80               1           0     0.0%
   ADDRESS                    72              53               1          18    25.0%
   AADHAAR                    39               0              37           2     5.1%
   CREDIT_CARD                25               0              23           2     8.0%
   CONFIDENTIAL_MARKER          5               0               0           5   100.0%
   BANK_ACCOUNT                5               0               4           1    20.0%
   HIGH_ENTROPY_SECRET          1               0               0           1   100.0%

```

## Secrets results

Samsung/CredData @ commit `c09c0c52`, built with its own `download_data.py` (all **337 repositories** fetched at their pinned
commits, 11,565 files, secret values obfuscated by the tool). The run happened in a Python 3.12 container in WSL2 with the dataset
mounted read-only. **67,564 labelled lines** were scored; 3 lines were skipped because their files were unreadable.

A line counts as **flagged** if the engine reports any credential-type entity (API key, AWS/Google/GitHub token, JWT, OAuth
token, password, private key, connection string, high-entropy secret) anywhere on it. CredData's **False** lines are hard
negatives (strings that other scanners flagged and humans rejected), so the false-positive rate is much harsher than on
ordinary text.

### Headline

| | Lines | Result |
|---|---|---|
| **True credentials detected** | 15,714 | **44.8 %** |
| **False positives on hard negatives** | 51,847 | **14.2 %** |

### By category (largest first; categories with ≥ 60 true lines)

| CredData category | True lines | Detection | False lines | FP rate |
|---|---|---|---|---|
| Key | 4,301 | 42.0 % | 20,817 | 6.0 % |
| Password | 2,743 | 57.5 % | 11,373 | **27.8 %** |
| UUID (used as a secret) | 2,539 | **6.1 %** | 3,716 | **59.0 %** |
| Secret (generic) | 1,571 | 26.2 % | 2,492 | 8.2 % |
| Auth | 1,278 | 68.7 % | 3,616 | 4.8 % |
| Token | 1,205 | 46.1 % | 5,287 | 2.0 % |
| PEM private key | 1,193 | **100.0 %** | 72 | 84.7 % |
| Basic Authorization | 692 | 87.1 % | 555 | 0.5 % |
| Bearer Authorization | 289 | 78.2 % | 0 | — |
| API | 253 | 60.1 % | 4,010 | 1.7 % |
| URL credentials | 227 | 27.8 % | 417 | 31.9 % |
| AWS client ID | 213 | 74.7 % | 33 | 75.8 % |
| JSON Web Token | 182 | **100.0 %** | 61 | 83.6 % |
| Nonce | 178 | 24.7 % | 110 | 8.2 % |
| NTLM token | 126 | 45.2 % | 0 | — |
| Credential | 96 | 70.8 % | 602 | 6.5 % |
| AWS S3 bucket | 92 | 62.0 % | 0 | — |
| Salt | 90 | 11.1 % | 130 | 10.0 % |
| JWK | 80 | 56.2 % | 3 | — |
| Dropbox app secret | 74 | 51.3 % | 145 | 26.2 % |
| PASERK keys | 72 | 72.2 % | 8 | 0.0 % |
| OTP / 2FA secret | 64 | 39.1 % | 3 | — |
| PASETO token | 63 | 96.8 % | 0 | — |
| NKEY seed | 60 | 80.0 % | 0 | — |

Vendor keys with a fixed prefix are caught when present, but the counts are tiny (1–24 lines each), so they are not
statistically meaningful: Azure access token 24/24, Google API key 13/13, Slack 12/15, and Stripe, GitHub classic, Anthropic,
Perplexity and Docker Swarm tokens at 100 % of 1–2 lines each. **0 %** on Twilio (30), Tencent WeChat app IDs (47), Firebase
domains (39), MailGun keys (8), command-line passwords (33) and base64-encoded PEM keys (12).

### What the numbers mean

* **Structured secrets are the engine's strength**: private keys, JWTs, HTTP Basic/Bearer credentials and prefixed cloud and
  vendor tokens are found 75–100 % of the time.
* **Unstructured secrets are its weakness**: a secret that looks like an ordinary value (a UUID used as an API key, a salt, a
  generic `secret = …`, a password in a SQL or shell command) is mostly missed. That is where CredData's human labels
  depend on context the rules do not read.
* **False positives are mostly by design, and some are real**: the engine flags *any* private-key block or JWT, including the
  example and placeholder ones CredData labels False (84.7 % / 83.6 %). For a gateway whose job is to stop anything
  credential-shaped leaving, that strictness is intended. The password (27.8 %), UUID (59.0 %) and URL-credential (31.9 %)
  false positives are real noise, from `password=`-style assignments with placeholder values and random-looking identifiers.
* Scoring is **per line**: a line counts as flagged if a credential-type entity is found anywhere on it, not necessarily on
  the labelled value, so detection on multi-value lines is slightly optimistic.
* **Nothing was tuned**, and CredData has no split, so all of it is held out. Improvements (context-aware passwords, UUID
  handling, more vendor formats) should be developed on a separate corpus and re-measured here.

### Raw output
```

== Samsung/CredData  (commit c09c0c52, 67564 labelled lines, 3 unreadable skipped, 126.6 s)
   OVERALL  true lines 15714: detection 44.8%   false lines 51847: false-positive rate 14.2%
   category                             true detection   false  FP rate
   Key                                  4301     42.0%   20817     6.0%
   Password                             2743     57.5%   11373    27.8%
   UUID                                 2539      6.1%    3716    59.0%
   Secret                               1571     26.2%    2492     8.2%
   Auth                                 1278     68.7%    3616     4.8%
   Token                                1205     46.1%    5287     2.0%
   PEM Private Key                      1193    100.0%      72    84.7%
   Basic Authorization                   692     87.1%     555     0.5%
   Bearer Authorization                  289     78.2%       0        -
   API                                   253     60.1%    4010     1.7%
   URL Credentials                       227     27.8%     417    31.9%
   AWS Client ID                         213     74.7%      33    75.8%
   JSON Web Token                        182    100.0%      61    83.6%
   Nonce                                 178     24.7%     110     8.2%
   NTLM Token                            126     45.2%       0        -
   Credential                             96     70.8%     602     6.5%
   AWS S3 Bucket                          92     62.0%       0        -
   Salt                                   90     11.1%     130    10.0%
   JWK                                    80     56.2%       3   100.0%
   Dropbox App secret                     74     51.3%     145    26.2%
   PASERK Keys                            72     72.2%       8     0.0%
   OTP / 2FA Secret                       64     39.1%       3    33.3%
   PASETO Token                           63     96.8%       0        -
   NKEY Seed                              60     80.0%       0        -
   Tencent WeChat API App ID              47      0.0%       0        -
   SQL Password                           44      6.8%      14     7.1%
   BASE64 Private Key                     39     64.1%       4     0.0%
   Firebase Domain                        39      0.0%       0        -
   AWS Multi                              34    100.0%      66   100.0%
   CMD Password                           33      0.0%     137     1.5%
   Twilio Credentials                     30      0.0%      39     0.0%
   Azure Access Token                     24    100.0%       0        -
   CURL Options                           17      0.0%       8     0.0%
   Slack Token                            15     80.0%       1   100.0%
   CMD ConvertTo-SecureString             13     15.4%       4    25.0%
   Google API Key                         13    100.0%       0        -
   BASE64 encoded PEM Private Key         12      0.0%       0        -
   WunderGraph API Key                    11    100.0%       0        -
   Google Multi                           11    100.0%       0        -
   MailGun API Key                         8      0.0%       0        -
   Grafana Provisioned API Key             7    100.0%      16    87.5%
   CURL User Password                      7      0.0%       2     0.0%
   Akamai Credentials                      6     33.3%       2     0.0%
   CMD Token                               6     50.0%       2     0.0%
   Salesforce Credentials                  6     16.7%       0        -
   Grafana Service Account Token           3    100.0%       0        -
   PostHog Credentials                     3    100.0%       0        -
   Google OAuth Access Token               3    100.0%       0        -
   Product Activation Key                  3    100.0%       0        -
   Stripe Credentials                      2    100.0%       0        -
   Postman Credentials                     2    100.0%       0        -
   Perplexity API Key                      2    100.0%       0        -
   Docker Swarm Token                      2    100.0%       0        -
   Github Classic Token                    1    100.0%       0        -
   Anthropic API Key                       1    100.0%       0        -
   Twilio Multi                            1      0.0%       0        -
   Google OAuth Refresh Token              1    100.0%       2   100.0%
   CMD Secret                              1      0.0%      18     5.6%
   Alibaba Access Key ID                   1      0.0%       0        -
   Alibaba Multi                           1    100.0%       0        -
   Other                                   0         -      20    50.0%
   Grafana Access Policy Token             0         -       2   100.0%
   Jira / Confluence PAT token             0         -       4    75.0%
   Facebook Access Token                   0         -       1     0.0%

```

