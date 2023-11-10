import requests
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup
import logging
import os
import re

# 환경 변수에서 API 인증 정보 가져오기
client_id = os.getenv('NAVER_CLIENT_ID')
client_secret = os.getenv('NAVER_CLIENT_SECRET')

if not client_id or not client_secret:
    raise ValueError("환경 변수 NAVER_CLIENT_ID와 NAVER_CLIENT_SECRET를 설정해주세요.")

# 로그 설정
def setup_logging(query):
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 파일 이름으로 사용할 수 없는 문자를 "_"로 대체
    safe_query = re.sub(r'[\\/*?:"<>|]', "_", query)
    log_filename = f"{safe_query}.log"
    
    logging.basicConfig(filename=os.path.join(log_dir, log_filename), 
                        level=logging.INFO, 
                        format='%(asctime)s:%(levelname)s:%(message)s', 
                        filemode='a')
    return log_filename  # 로그 파일 이름을 반환하도록 함

# URL 처리를 위한 헬퍼 함수
def build_url(url, path):
    return urlparse(url)._replace(path=path, query="").geturl()

# 네이버 검색 결과 가져오기
def get_naver_search_results(query):
    search_url = f"https://openapi.naver.com/v1/search/webkr.json?query={quote(query)}"
    search_headers = {
        "X-Naver-Client-Id": client_id,
        "X-Naver-Client-Secret": client_secret
    }
    try:
        search_response = requests.get(search_url, headers=search_headers, timeout=5)
        links = []

        if search_response.status_code == 200:
            search_data = search_response.json()
            items = search_data.get('items', [])
            for item in items:
                links.append(item['link'])
        else:
            logging.error(f"Error retrieving search results: {search_response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during search request: {e}")
    
    return links

# 콘텐츠 검사와 내부 링크 분석
def analyze_content(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        internal_links = [a['href'] for a in soup.find_all('a', href=True) if 'http' not in a['href']]
        # 내부 링크 로깅
        logging.info(f"Internal links found at {url}: {internal_links}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Content analysis failed for {url}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during content analysis for {url}: {e}")

# URL 분석 (보안 헤더 포함)
def analyze_url(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        logging.info(f"Analyzing URL: {url}")

        # SSL/TLS 사용 여부 확인
        if response.url.startswith('https://'):
            logging.info(f"SSL/TLS is used for {url}")
        else:
            logging.warning(f"SSL/TLS is not used for {url}")

        # 보안 헤더 분석
        security_headers_to_check = [
            'X-Frame-Options', 
            'X-Content-Type-Options', 
            'Content-Security-Policy',
            'Strict-Transport-Security', 
            'X-XSS-Protection'
        ]

        for header in security_headers_to_check:
            if header in headers:
                logging.info(f"{header} is set for {url}")
            else:
                logging.warning(f"{header} is not set for {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"URL analysis failed for {url}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during URL analysis for {url}: {e}")

# robots.txt 준수 여부 확인
def check_robots_txt(url):
    robots_url = build_url(url, "/robots.txt")
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            logging.info(f"robots.txt found for {url}")
        else:
            logging.warning(f"robots.txt not found for {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking robots.txt for {url}: {e}")

# security.txt 파일 존재 여부 확인
def check_security_txt(url):
    security_url = build_url(url, "/.well-known/security.txt")
    try:
        response = requests.get(security_url, timeout=5)
        if response.status_code == 200:
            logging.info(f"security.txt found for {url}")
        else:
            logging.warning(f"security.txt not found for {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking security.txt for {url}: {e}")

# 불필요한 파일 노출 검사
def check_exposed_files(url):
    files_to_check = ['.git', '.env', 'config.php']
    for file in files_to_check:
        file_url = build_url(url, f"/{file}")
        try:
            response = requests.get(file_url, timeout=5)
            if response.status_code == 200:
                logging.warning(f"Exposed file found: {file_url}")
            else:
                logging.info(f"No exposed file found: {file_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking for exposed files at {url}: {e}")

# 사이트의 메타데이터 분석
def analyze_metadata(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        metas = soup.find_all('meta')
        meta_data = {meta.get('name', meta.get('property')): meta.get('content') for meta in metas if meta.get('name') or meta.get('property')}
        logging.info(f"Metadata found for {url}: {meta_data}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error analyzing metadata for {url}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during metadata analysis for {url}: {e}")

# 메인 함수
def main(query):
    log_filename = setup_logging(query)

    urls = get_naver_search_results(query)
    for url in urls:
        analyze_url(url)
        analyze_content(url)
        check_robots_txt(url)
        check_security_txt(url)
        check_exposed_files(url)
        analyze_metadata(url)
        logging.info(f"Finished analysis for {url}")
    return log_filename  # 로그 파일 이름 반환


# 스크립트 실행
if __name__ == "__main__":
    search_query = input("Enter the search term: ").strip()
    if not search_query:
        raise ValueError("검색어를 입력해야 합니다.")
    main(search_query)

    log_file = main(search_query)
    print(f"Analysis complete. Log file created: {log_file}")
