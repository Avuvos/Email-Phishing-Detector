import requests


# computes the edit distance between two strings using dynamic programming
# I'm familiar with this algorithm, this code has been tested many times and it works.
def calculate_edit_distance(s: str, t: str) -> int:
    n, m = len(s), len(t)
    inf = 10 ** 9
    dp = [[inf] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        dp[i][0] = i
    for i in range(m + 1):
        dp[0][i] = i

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if s[i - 1] == t[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[n][m]


# gets the api key from the specified file
def get_api_key(filename: str) -> str:
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print("No api key provided so cannot perform url test using virustotal")
        return ""


HTTP_OK = 200
api_key = get_api_key("secret.txt")


# returns the number of malicious votes, using virustotal api to check that.
# following https://docs.virustotal.com/reference/scan-url
def get_malicious_votes_count(url: str) -> int:
    if not api_key:
        return 0
    # print(f"current url being checked is {url}")
    endpoint = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(endpoint, data=data, headers=headers)
    if response.status_code == HTTP_OK:
        analysis_id = response.json()["data"]["id"]
        endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        response = requests.get(endpoint, headers=headers)
        if response.status_code == HTTP_OK:
            stats_data = response.json()["data"]["attributes"]["stats"]
            malicious_votes = stats_data["malicious"]
            harmless_votes = stats_data["harmless"]
            # print(f"malicious votes: {malicious_votes}")
            # print(f"harmless votes: {harmless_votes}")
            return malicious_votes
    return -1
