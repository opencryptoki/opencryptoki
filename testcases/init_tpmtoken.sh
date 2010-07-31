#!/usr/bin/expect -f


spawn tpmtoken_init -y
set timeout 1
expect {
    "Enter the TPM security officer password: " { send "76543210\r"}
}

set timeout 10

expect {
    "Enter new password: "      { send "76543210\r" }
}

expect {
    "Confirm password: "        { send "76543210\r" }
}

expect {
    "Enter new password: "      { send "01234567\r" }
}

expect {
    "Confirm password: "        { send "01234567\r" }
}
