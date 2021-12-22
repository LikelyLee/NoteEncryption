## Obsidian Note Encryption Plugin

This is a plugin to encrypt / decrypt the active note in [Obsidian.md](https://obsidian.md/).

There are two modes to provide the password:

1. There is a textbox in plugin setting page, where you can leave your password here. Please note that the password here is always shown as plaintext, and since it will be stored in the configuration files under your Obsidian folder, it may be acquired by other plugin / app or even anyone else. With the password set here, you don't have to enter it everytime.

2. Enter the password after clicking on the ribbon button. With this approach, you need to provide the password everytime, the plugin will never remember the password. So you need to make sure you can remember it, there is NO way to find back your password.

## How to use this plugin

After installing the plugin, it creates a button called "Note Encryption" on the left side of the ribbon area. Simply click on it, a dialog will pop up to ask for the password. Enter your password, a simple policy check will let you know if your password is long enough. Then click on "Submit" button, your active note will be encrypted and closed.

You can click on the encrypted note, it will shows the cipher text on the editor area. Note name and extension are neverencrypted, so you can still rely on Obsidian to sync or manage as always.

If the active note is the encrypted one, then click on the "Note Encryption" button will ask for the password to decrypt it. Again, it closes the current note, and you can re-open it to check the plaintext.

If the password is set on the setting page, then click the "Note Encryption" button will not ask for password any more.

## Settings of the plugin

There are 3 items can be set:

1. Password: you can enter your password here for persistent use. i.e. no need to enter password everytime. Please do note the possiblity of leaking your password to other parties.

2. Persistent Password toggle: If you have the password set above, enable this toggle to store your password for future use. If this is turned to disable, you still have to enter the password everytime.

3. Move to trash toggle: It's designed to be a fail safe mechanism. In case anything goes wrong, the original note will be moved into system's trash after the encryption / decryption. If this is disabled, the original note will be permanently deleted.

## Why this note deletion involved?

I tried to use the Obsidian API writeLine() or setValue() functions to otput the result back into the note, the tricky thing is once the note is encrypted / decrypted, you can simply undo (ctrl + z) it to turn it back... Well you can switch to other note and then switch back to make the undo fail, but it feels not secure.

So I go for another way around, after writing the result back to the note, the plugin delete the original note, and create a new one with same name under the same folder, so undo will never work. BUT to be honest, I'm not a good coder, so I don't know if this may cause other issues or not, that's why the "Move to trash" is rovided...

## Security strength

The password is hashed by SHA-512 and left into the encrypted note for comparison. You can use different password for different notes with the "Persistent Password" set to false. But please DO REMEMBER your passwords since all the processes on the password by this plugin is one-way method.

The password is also converted into encryption key by using PBKDF2 with SHA-512. This key never gets stored on anywhere, everytime the key is re-generated by the password.

The note is encrypted line by line with AES-256-GCM, key is generated as above mentioned. Since each line is encrypted respectively, so the tamper happens on one line will not affect other lines. If there is anything wrong to some lines in ciphertext, there is still a chance to decrypt other parts of the note.
