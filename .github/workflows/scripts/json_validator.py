
import json
try:
    with open('system_test_mapping.json', 'r') as file:
        json.load(file)
    print('The file system_test_mapping.json looks good.')
except json.JSONDecodeError as e:
    print(f'JSON format error in system_test_mapping.json: {e}')
    exit(1)

