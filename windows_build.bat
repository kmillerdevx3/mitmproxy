set VERSION=%1

pip uninstall -y mitmproxy

tox -- --verbose --cov-report=term
tox -e wheel

pip install release\dist\mitmproxy-%VERSION%-py3-none-any.whl

tox -e rtool -- bdist

copy /Y release\build\binaries\windows\mitm*.exe "C:\Program Files (x86)\mitmproxy\bin"
