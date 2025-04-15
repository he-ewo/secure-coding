## Tiny Second-hand Shopping Platform 개발

가상환경을 만들어 준다.
```
git clone https://github.com/he-ewo/secure-coding.git
conda env create -f enviroments.yaml
```

서버를 실행한다.
```
python app.py
```

로컬호스트로 서버를 접속한다.
```
https://127.0.0.1:5000 
```

만약 https로 접속이 되지 않는다면 또는 ngrok을 사용하기 위해서는 app.py 파일의 맨 아랫부분에서 아래의 코드를 찾아 ssl_context 부분을 제거하고 다시 서버를 실행한다.
```
if __name__ == '__main__':
    init_db()  
    socketio.run(app, ssl_context=('cert.pem', 'key.pem'), debug=False) 
```

이렇게 수정하면 된다.
```
if __name__ == '__main__':
    init_db()  
    socketio.run(app, debug=False) 
```

웹사이트에 접속하면 회원가입 후 로그인을 하여 중고거래 플랫폼을 이용할 수 있다. 관리자 페이지에 접근하기 위해서는 아래의 사용자명과 비밀번호로 로그인하고, https://127.0.0.1:5000/admin 으로 접근한다.
```
jangheewon // 관리자 사용자명
jang0209** // 관리자 비밀번호
https://127.0.0.1:5000/admin // 관리자 페이지
```
