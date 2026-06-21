@"
[pytest]
asyncio_mode = auto
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
"@ | Out-File -FilePath pytest.ini -Encoding utf8

@"
pytest==8.3.3
pytest-asyncio==0.24.0
"@ | Out-File -FilePath requirements-dev.txt -Encoding utf8