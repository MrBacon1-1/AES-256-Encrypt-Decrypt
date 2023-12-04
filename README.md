# AES-256-Encrypt-Decrypt
Simple Python Script Using AES-256 To Encrypt And Decrypt Text

# Contents

1. [Requirements](#requirements)
2. [Arguments](#arguments)
3. [Usage Examples](#usage)
4. [Support Me]()

# Requirements 

If you download an exe from the releases you do not need to worry about requirements!

`pip install cryptography psutil`

# Arguments

Options:

  -h, --help                  Shows the help message.
  -e, --encrypt               Encrypt the string.
  -d, --decrypt               Decrypt the string.
  -s STRING, --string STRING  Input a string to be encrypted or decrypted.
  -f FILE, --file FILE        Input a file path to be encrypted or decrypted.
  

# Usage

Encrypt String:

# It may break sometimes if '\' is used but if it is done via a file it will work fine

`python AES-256.py -e -s "Test"`

Decrypt String:

If you try to decrypt a string that is not encrypted it will cause an error!

`python AES-256.py -d -s "<Encrypted String>"`

Encrypt File:

You can use a path to any file it should work with all file extensions.

`python AES-256.py -e -f "test.txt"`

Decrypt File:

If you try to decrypt a file that is not encrypted it will cause an error!

`python AES-256.py -d -f "test.txt"`

