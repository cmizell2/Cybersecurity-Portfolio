# Algorithm for file updates in Python
# Removes IP addresses that no longer have access from an allow list file.
# Based on the Google Cybersecurity Professional Certificate (Coursera).


def update_file(import_file, remove_list):
    """Remove every IP address in remove_list from import_file."""

    # Open the allow list file and read its contents
    with open(import_file, "r") as file:
        ip_addresses = file.read()

    # Convert the string into a list of IP addresses
    ip_addresses = ip_addresses.split()

    # Loop through the list and remove any IP address on the remove list
    for element in remove_list:
        if element in ip_addresses:
            ip_addresses.remove(element)

    # Convert the list back into a string
    ip_addresses = "\n".join(ip_addresses)

    # Rewrite the file with the updated allow list
    with open(import_file, "w") as file:
        file.write(ip_addresses)


if __name__ == "__main__":
    remove_list = ["192.168.97.225", "192.168.158.170", "192.168.201.40", "192.168.58.57"]

    update_file("allow_list.txt", remove_list)

    # Verify the file was updated
    with open("allow_list.txt", "r") as file:
        print(file.read())
