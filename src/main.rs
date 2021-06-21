use std::{
	convert::TryFrom,
	time::{
		SystemTime,
		UNIX_EPOCH,
	},
};

use serde::Deserialize;
use totp_lite::{Sha1};

#[derive (Deserialize)]
struct FreeOtpBackup {
	#[serde (rename = "tokenOrder")]
	token_order: Vec <String>,
	tokens: Vec <FreeOtpToken>,
}

#[derive (Deserialize)]
struct FreeOtpToken {
	_algo: String,
	_counter: u64,
	_digits: u64,
	
	#[serde (rename = "issuerExt")]
	_issuer_ext: String,
	_label: String,
	_period: u64,
	secret: Vec <i8>,
	
	#[serde (rename = "type")]
	_password_type: String,
}

fn main () {
	let filename = std::env::args ().skip (1).next ().expect ("First arg should be freeotp-backup.json file");
	
	let json_s = std::fs::read_to_string (&filename).expect ("Couldn't read that file");
	
	let backup_data: FreeOtpBackup = serde_json::from_str (&json_s).expect ("Couldn't parse file as FreeOTP backup JSON");
	
	let seconds: u64 = SystemTime::now ().duration_since (UNIX_EPOCH).unwrap ().as_secs ();
	if false {
		println! ("Seconds since epoch: {}", seconds);
	}
	
	for (name, token) in backup_data.token_order.iter ().zip (backup_data.tokens.iter ()) {
		let secret: Vec <u8> = token.secret.iter ().map (|why_in_the_wide_world_of_sports_is_this_signed| u8::try_from ((*why_in_the_wide_world_of_sports_is_this_signed as i32 + 256) % 256).expect ("I got the math wrong")).collect ();
		
		// Dump secrets for debugging
		if false {
			println! ("{}: {:?}", name, token.secret);
			println! ("{}: {:?}", name, secret);
		}
		
		let totp: String = do_totp (seconds, &secret);
		println! ("{}: {}", name, totp);
	}
	
	// Well-known secret for debugging
	
	if false {
		let secret_b32: &str = "SECRETTT";
		let secret = base32::decode (base32::Alphabet::RFC4648 { padding: false }, secret_b32).unwrap ();
		
		println! ("{}: {:?}", "test", secret);
		println! ("test: {}", do_totp (seconds, &secret));
	}
}

fn do_totp (seconds: u64, secret: &[u8]) -> String {
	// This is the only kind of TOTP I have ever entered in the wild. Strangely
	// it's _not_ the default for totp_lite. Anyway, I didn't implement the others.
	
	totp_lite::totp_custom::<Sha1> (totp_lite::DEFAULT_STEP, 6, &secret, seconds)
}
