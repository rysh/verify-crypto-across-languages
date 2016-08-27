package jp.rysh.crypt.aes;

import static org.junit.Assert.*;

import java.security.Key;
import java.util.List;

import org.hamcrest.core.Is;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import io.github.benas.randombeans.api.EnhancedRandom;
import jp.rysh.crypto.aes.Aes;

@RunWith(Theories.class)
public class AesTest {

	@DataPoints({ "keys" })
	public static List<String> keys() {
		return EnhancedRandom.randomListOf(100, String.class);
	}

	@DataPoints({ "words" })
	public static List<String> words() {
		return EnhancedRandom.randomListOf(100, String.class);
	}

	@Theory
	public void createKey(@FromDataPoints(value = "keys") String keyString) throws Exception {
		Aes aes = new Aes();
		Key key = aes.createKey(keyString);
		assertThat(key.getEncoded().length, Is.is(128 / 8));
	}

	@Theory
	public void encdoe(@FromDataPoints(value = "words") String source, @FromDataPoints(value = "keys") String keyString)
			throws Exception {
		Aes aes = new Aes();
		Key key = aes.createKey(keyString);
		byte[] encoded = aes.encode(source.getBytes(), key);
		// System.out.println(Arrays.toString(encoded));
		byte[] decoded = aes.decode(encoded, key);
		assertThat(String.format("source:%s, key:%s", source,keyString), new String(decoded), Is.is(source));
	}

}
