import { App, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting } from 'obsidian';
import * as crypto from 'crypto';

const pwWrong = '%%PASSWORD_MISMATCH%%';

const decode = (str: string):string => Buffer.from(str, 'base64').toString('binary');
const encode = (str: string):string => Buffer.from(str, 'binary').toString('base64');

// Classes and interfaces for the plugin
interface NoteEncryptionSettings {
	password : string;		// the attachment folder that Obsidian stores images in
	persistent : boolean;	// if the password is persistent
	trash : boolean	// if the password is persistent
}

const DEFAULT_SETTINGS: NoteEncryptionSettings = {
	password: 'Enter the password',
	persistent: false,
	trash: true
}

// password check, compare with the password policy
function passwordCheck (password : string) {
	if (password == '') {
		console.log("Password is empty, please re-enter.");
		new Notice("Password is empty, please re-enter.");
		return 0;
	}
	else if (password.length <= 7) {
		console.log("Password is too short, it must be at least 7 characters.");
		new Notice("Password is too short, it must be at least 7 characters.");
		return 0;
	}
	else {
		return 1;
	}
}

// convert password to digest for comparison, and the key for encryption / decryption
function process_password(direction : string, pw : string, salt : string) {
	// determine the directon, if it is encryption then salt is randomly generated
	if (direction == "ENC") {
		console.log("The note is going to be ENCRYPTED ...");
	}
	else {
		console.log("The note is going to be DECRYPTED ...");
	}

	// calculate digest of password for comparison
	const HASH = crypto.createHash('sha512');	  
	HASH.update(pw);
	const digest = HASH.digest('hex');

	// derive password to aes 256 bits key
	const key = crypto.pbkdf2Sync(pw, salt, 100000, 32, 'sha512');

	return [digest, key.toString('hex')]
}

// aes 256 gcm encryption
function encrypt_AES_GCM (plainText: string, key : string) {
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(64);

	const encKey = Buffer.from(key, "hex");
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(String(plainText), 'utf8'),
      cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

// aes 256 gcm decryption
function decrypt_AES_GCM (cipherText: string, key : string) {
    const stringValue = Buffer.from(String(cipherText), 'base64');

    const salt = stringValue.slice(0, 64);
    const iv = stringValue.slice(64, 64 + 16);
    const tag = stringValue.slice(64 + 16, 64 + 16 + 16);
    const encrypted = stringValue.slice(64 + 16 + 16);

	const decKey = Buffer.from(key, "hex");

	let plainText = '';

	try {
		const decipher = crypto.createDecipheriv('aes-256-gcm', decKey, iv);
		decipher.setAuthTag(tag);
		plainText = decipher.update(encrypted) + decipher.final('utf8')
	}
	catch (error) {
		console.log(error);
		new Notice('There is error happened during decryption, the ciphertext maybe tampered.');
		plainText = cipherText;
	}

    return plainText;
}

// perform encryption or decryption on the active note
function EncDec (pw : string, lines : string []) : string {
	const view = this.app.workspace.getActiveViewOfType(MarkdownView);
	if (view) {
		// check if the note is encrypted, then decrypt it
		if (view.editor.getLine(0).startsWith("PASSWORD_PROTECTED_NOTE")) {
			console.log("Starting note decryption");
			new Notice("Starting note decryption");

			let plainContent = '';
			let digest = '';
			let key = '';

			for (let i = 1; i < lines.length; i++) {
				const line = lines[i];
				let final_text = line;

				if ((final_text == '\n') || (final_text == '')) {
					continue;
				}
				// read out the digest of password and the salt for pbkdf2
				else if (final_text.startsWith("PW_DIGEST")) {
					final_text = final_text.replace('\n', '');
					const read_digest = decode(final_text.split('|')[1]);
					const read_salt = decode(final_text.split('|')[2]);

					// ask for the password
					[digest, key] = process_password("DEC", pw, read_salt);


					if (digest != read_digest) {
						console.log("Password mismatch! Please enter correct password!");
						new Notice("Password mismatch! Please enter correct password!");
						return pwWrong;
					}
					else {
						console.log("Password is correct, decrypting ...");
						new Notice("Password is correct, decrypting ...");
						continue;
					}
				}
				else {
					// decrypt each line of the original md file
					final_text = decrypt_AES_GCM(final_text, key) +  "\n";

					// write to the new md file
					plainContent += final_text;
				}
			}

			console.log("Decryption is done!");
			new Notice('Note decryption complete');

			return plainContent;
		}
		// check if the note is not encrypted, then encrypt it
		else {
			console.log("Starting note encryption");
			new Notice("Starting note encryption");

			// ask for the password
			const salt = crypto.randomBytes(16).toString('hex');
			const [digest, key] = process_password("DEC", pw, salt);
			
			console.log("Password is entered, encrypting ...");

			let cipherContent = '';

			// add indicator and password digest into the note
			cipherContent += "PASSWORD_PROTECTED_NOTE\n";
			cipherContent += "PW_DIGEST|" + encode(digest) + "|" + encode(salt) + "\n";

			for (let i = 0; i < lines.length; i++) {
				const line = lines[i];
				let final_text = line;

				// encrypt each line of the original md file
				final_text = encrypt_AES_GCM(line, key) +  "\n";
			
				// write ciphertext to the new md file
				cipherContent += final_text;
			}
			
			console.log("Encryption is done!");
			new Notice('Note encryption complete');

			return cipherContent;
		}
	}
}

export default class ExptoHexoPlugin extends Plugin {
	settings: NoteEncryptionSettings;

	async onload() {
		await this.loadSettings();

		// This creates an icon in the left ribbon.
		const ribbonIconEl = this.addRibbonIcon('open-vault', 'Note Encryption', async (evt: MouseEvent) => {
			// Called when the user clicks the icon.

			const noteFile = this.app.workspace.getActiveFile();
			const content = await this.app.vault.read(noteFile); 
			const lines = content.split('\n');

			if (this.settings.persistent == true) {
				// use the password set in settings page
				console.log('Use the password set in Settings page');
				const newContent = EncDec(this.settings.password, lines);
				
				if (newContent != pwWrong) {
					this.app.vault.trash(noteFile, this.settings.trash);
					this.app.vault.create(noteFile.path, newContent);
				}
			}
			else {
				// show the dialog to ask user to enter password
				console.log('Use the password entered in the dialog');
				const inputPW = '';
				new NoteEncryptionModal(this.app, (inputPW) => {
					new Notice(`The entered password is: ${inputPW}`);

					const newContent = EncDec(inputPW, lines);
			
					if (newContent != pwWrong) {
						this.app.vault.trash(noteFile, this.settings.trash);
						this.app.vault.create(noteFile.path, newContent);
					}
				}).open();
			}
		});
		
		this.addSettingTab(new ExptoHexoSettingTab(this.app, this));
	}

	onunload() {
		if (!this.settings.persistent) {
			this.settings.password = '';
		}
	}

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}
}

// Items on the Settings page
class ExptoHexoSettingTab extends PluginSettingTab {
	plugin: ExptoHexoPlugin;

	constructor(app: App, plugin: ExptoHexoPlugin) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display(): void {
		const {containerEl} = this;

		containerEl.empty();

		containerEl.createEl('h2', {text: 'Note Ecnryption Settings Page'});

		new Setting(containerEl)
			.setName('Password')
			.setDesc('Your password used to encrypt on the note')
			.addText(text => text
				.setPlaceholder('Enter the password')
				.setValue(this.plugin.settings.password)
				.onChange(async (value) => {
					this.plugin.settings.password = value;
					await this.plugin.saveSettings();
				}));

		new Setting(containerEl)
			.setName("Persistent Password")
			.setDesc('You can set and use the password above if "Persistent Password" is enabled. NOTE that if the password is set here, it will stored with the plugin, where other malicious app or plugins may access to it.')
			.addToggle(show => show
				.setValue(this.plugin.settings.persistent)
				.onChange((value) => {
				if (value == true) {
					this.plugin.settings.persistent = true;
					console.log('Persistent Password is enabled.');
				}
				else {
					this.plugin.settings.persistent = false;
					this.plugin.settings.password = '';
					console.log('Persistent Password is disabled.');
				}
				this.plugin.saveSettings();
			}));

		new Setting(containerEl)
			.setName("Move to trash")
			.setDesc('The original note will be moved to system trash or directly deleted once encryption / decryption is complete.')
			.addToggle(show => show
				.setValue(this.plugin.settings.trash)
				.onChange((value) => {
				if (value == true) {
					this.plugin.settings.trash = true;
					console.log('Move to system trash is enabled.');
				}
				else {
					this.plugin.settings.trash = false;
					console.log('Move to system trash is disabled.');
				}
				this.plugin.saveSettings();
			}));
	}
}

export class NoteEncryptionModal extends Modal {
	password: string;
	onSubmit: (password: string) => void;
  
	constructor(app: App, onSubmit: (password: string) => void) {
	  	super(app);
		this.onSubmit = onSubmit;
	}
  
	onOpen() {
		const { contentEl } = this;
	
		contentEl.createEl("h2", { text: "Please enter the password" });
	
		new Setting(contentEl)
			.setName("Password")
			.addText((text) =>
			text.onChange((value) => {
				this.password = value;
			}));
	
		new Setting(contentEl)
			.addButton((btn) =>
			btn
				.setButtonText("Submit")
				.setCta()
				.onClick(() => {
					if (passwordCheck(this.password)) {
						this.close();
						this.onSubmit(this.password);
					}
					else {
						new Notice('Password does not meet the policy.');
					}
				}));
	}		

	onClose() {
		const { contentEl } = this;
		contentEl.empty();
	}
}