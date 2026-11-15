# Solo Leveling: ARISE OVERDRIVE — Save Decryptor & Editor

A save decryptor and editor for **Solo Leveling: ARISE OVERDRIVE**, supporting PC and PS5 save workflows.

This tool allows you to:
- Decrypt and edit PC save files.
- Re-encrypt modified PC saves.
- Convert PC saves into a format intended for PS5.
- Transfer edited PC save data to PS5.

## ⚠️ Important Notice — PS5 Support

**Direct PS5 save decryption is currently unsupported.**

The decryption method for the PS5 version is still unknown, so you cannot directly load or decrypt an existing PS5 save with this tool.

However, you can transfer a PC save to PS5 using the following workaround:

- Load and edit your PC save.
- Use the **Save and Encrypt for Other Platform** option.
- The PS5 save is currently generated using the default encryption key: `1234`.

This allows you to prepare a PC save for transfer to PS5.

## How to Use

### 1. Load Your Save
1. Enter your Steam ID in the field at the top of the editor.
2. Load your PC save file.

### 2. Edit Your Save
Make the desired changes using the save editor.

### 3. Save Your Changes

Choose the appropriate save option:

| Option | Purpose |
|---|---|
| **Save and Re-encrypt** | Saves and re-encrypts your modified PC save. |
| **Save and Encrypt for Other Platform** | Generates an encrypted save intended for PS5 transfer. |

### 4. Transfer Your Save to PS5

If you are transferring your edited PC save to PS5:

::Load you PC save with the correct steam id first::

1. Select **Save and Encrypt for Other Platform**.
2. Locate the generated `.db` file.
3. Rename the file to `SaveData` (remove the `.db` extension).
4. Transfer the renamed file to your PS5.
5. Place it in the appropriate game save location, under `GameSlot1`, replacing the existing save file.

**Important:** Back up your original PS5 save before replacing it.

## Compatibility

| Platform | Support |
|---|---|
| PC (Steam) | Decrypt, edit, and re-encrypt |
| PS5 | Direct save decryption currently unsupported |
| PC → PS5 | Save conversion workflow using the default key `1234` |

## Disclaimer

This is an unofficial community project and is not affiliated with or endorsed by Netmarble or the developers of Solo Leveling: ARISE OVERDRIVE.

Use at your own risk. Always keep backups of your original save files.

