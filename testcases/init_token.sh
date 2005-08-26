#!/usr/bin/expect -f

set timeout 5

spawn /usr/lib/pkcs11/methods/pkcsconf -c [lindex $argv 0] -I
expect "Enter the SO PIN: "
sleep .2
send "87654321\r"
sleep .2
expect "label: "
sleep .2
send "ibmtest\r"
sleep .2
expect eof

spawn /usr/lib/pkcs11/methods/pkcsconf -c [lindex $argv 0] -P
expect "Enter the SO PIN: "
sleep .2
send "87654321\r"
sleep .2
expect "Enter the new SO PIN: "
sleep .2
send "76543210\r"
sleep .2
expect "Re-enter the new SO PIN: "
sleep .2
send "76543210\r"
sleep .2
expect eof

spawn /usr/lib/pkcs11/methods/pkcsconf -c [lindex $argv 0] -P
expect "Enter the SO PIN: "
sleep .2
send "76543210\r"
sleep .2
expect "Enter the new SO PIN: "
sleep .2
send "87654321\r"
sleep .2
expect "Re-enter the new SO PIN: "
sleep .2
send "87654321\r"
sleep .2
expect eof

spawn /usr/lib/pkcs11/methods/pkcsconf -c [lindex $argv 0] -u
expect "Enter the SO PIN: "
sleep .2
send "87654321\r"
sleep .2
expect "Enter the new user PIN: "
sleep .2
send "01234567\r"
sleep .2
expect "Re-enter the new user PIN: "
sleep .2
send "01234567\r"
sleep .2
expect eof

spawn /usr/lib/pkcs11/methods/pkcsconf -c [lindex $argv 0] -p
expect "Enter user PIN: "
sleep .2
send "01234567\r"
sleep .2
expect "Enter the new user PIN: "
sleep .2
send "12345678\r"
sleep .2
expect "Re-enter the new user PIN: "
sleep .2
send "12345678\r"
sleep .2
expect eof
