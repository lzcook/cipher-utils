import com.lzc.lib.util.cipher.hash.SM3Utils;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author lzc
 * 2019/2/25 15:22
 */
public class SM3Test {
    private String content = "hello world";
    private String expectedHash = "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88";

    @Test
    public void test() {
        System.out.println(SM3Utils.sm3(content));
        Assert.assertEquals( SM3Utils.sm3(content), expectedHash);
    }

}
