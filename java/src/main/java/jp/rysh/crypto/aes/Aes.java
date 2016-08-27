package jp.rysh.crypto.aes;

import java.security.Key;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Aes {
	public static void main(String[] args) {
		Key skey = makeKey1(128);

		// 暗号化
		byte[] enc = encode1("hoge".getBytes(), skey);
		// 復号化
		byte[] dec = decode1(enc, skey);

		System.out.println(new String(dec));
	}

	/**
	 * 秘密鍵をバイト列から生成する
	 * @param key_bits 鍵の長さ（ビット単位）
	 */
	public static Key makeKey1(int key_bits) {
		// バイト列
		byte[] key = new byte[key_bits / 8];

		// バイト列の内容（秘密鍵の値）はプログラマーが決める
		for (int i = 0; i < key.length; i++) {
			key[i] = (byte) (i + 1);
		}

		System.out.println(key);
		return new SecretKeySpec(key, "AES");
	}

	/**
	 * 暗号化
	 */
	public static byte[] encode1(byte[] src, Key skey) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skey);
			return cipher.doFinal(src);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 復号化
	 */
	public static byte[] decode1(byte[] src, Key skey) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skey);
			return cipher.doFinal(src);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	private static int keyBits = 128;
	public Key createKey(String seed) {


		byte[] key = new byte[keyBits / 8];

		// バイト列の内容（秘密鍵の値）はプログラマーが決める
		byte[] bytesOfSeed = seed.getBytes();
		IntStream.range(0, bytesOfSeed.length).filter(i -> i < key.length).forEach(i -> key[i] = bytesOfSeed[i]);
		return new SecretKeySpec(key, "AES");
	}

	public byte[] encode(byte[] src, Key key) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(src);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] decode(byte[] encoded, Key key) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(encoded);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
