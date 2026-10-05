# Python Automation: Allow List Update

**Scenario from the Google Cybersecurity Professional Certificate (Coursera)**

## Scenario
A health care company controls access to restricted content with an allow list of IP addresses. I built a Python algorithm that automatically removes IP addresses that should no longer have access.

## How It Works
1. Opens and reads the allow list file (`with open()`, `.read()`)
2. Converts the contents into a list of IP addresses (`.split()`)
3. Loops through the remove list and deletes matching IP addresses (`for`, `if`, `.remove()`)
4. Converts the list back to text and rewrites the file (`.join()`, `.write()`)
5. Wraps all steps in a reusable function: `update_file(import_file, remove_list)`

## Improvement
The original lab looped through `ip_addresses` while removing items from it, which can skip items. My final script loops through `remove_list` instead, so every address on the remove list is checked.

## How to Run
Run the script from the folder containing both files: `python update_allow_list.py`

## Files
- [update_allow_list.py](./update_allow_list.py): the Python script
- [allow_list.txt](./allow_list.txt): sample allow list (fictional IP addresses)
- [Algorithm_for_File_Updates.pdf](./Algorithm_for_File_Updates.pdf): report explaining each step of the code

## Skills Demonstrated
Python · File handling · Loops and conditionals · Functions · Security automation · Access control
