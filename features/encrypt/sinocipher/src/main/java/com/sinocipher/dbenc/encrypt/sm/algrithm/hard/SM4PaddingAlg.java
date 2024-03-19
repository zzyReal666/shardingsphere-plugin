package com.sinocipher.dbenc.encrypt.sm.algrithm.hard;

import com.zayk.sdf.api.provider.ZaykJceGlobal;
import com.zayk.sdf.api.sdk.ZaykSDF;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.shardingsphere.encrypt.exception.algorithm.EncryptAlgorithmInitializationException;
import org.apache.shardingsphere.encrypt.spi.EncryptAlgorithm;
import org.apache.shardingsphere.encrypt.spi.EncryptAlgorithmMetaData;
import org.apache.shardingsphere.infra.algorithm.core.context.AlgorithmSQLContext;
import org.apache.shardingsphere.infra.exception.core.ShardingSpherePreconditions;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * @author zzypersonally@gmail.com
 * @description 硬件加密算法
 * @since 2024/3/18 13:55
 */
@EqualsAndHashCode
public final class SM4PaddingAlg implements EncryptAlgorithm {


    static {
        //路径 当前项目路径
        String path = System.getProperty("user.dir");
        System.out.println("当前项目路径：" + path);
        sdf = ZaykSDF.getInstance(path + "/config/zayk4j.ini");
    }

    private static ZaykSDF sdf;

    private static final String KEY_INDEX = "key-index";

    private static final String IV = "iv";

    private static final String MODE = "mode";

    private static final int IV_LENGTH = 16;

    private static final String SM4_PADDING = "sm4-padding";     //暂时不用

    private static final Set<String> MODES = new HashSet<>(Arrays.asList("ECB", "CBC"));

    private static final Set<String> PADDINGS = new HashSet<>(Arrays.asList("PKCS5Padding", "PKCS7Padding"));  //暂时不用

    private int keyIndex;

    private byte[] sm4Iv;

    private int sm4Mode;

    @Getter
    private EncryptAlgorithmMetaData metaData;

    @Override
    public void init(final Properties props) {
        sm4Mode = createSm4Mode(props);
        keyIndex = createSm4Key(props);
        sm4Iv = createSm4Iv(props, sm4Mode);
        metaData = new EncryptAlgorithmMetaData(true, false, false);
    }

    private int createSm4Mode(final Properties props) {
        ShardingSpherePreconditions.checkState(props.containsKey(MODE), () -> new EncryptAlgorithmInitializationException("SM4", String.format("%s can not be null", MODE)));
        String mode = String.valueOf(props.getProperty(MODE)).toUpperCase();
        ShardingSpherePreconditions.checkState(MODES.contains(mode), () -> new EncryptAlgorithmInitializationException("SM4", "Mode must be either CBC or ECB"));
        switch (mode) {
            case "CBC":
                return ZaykJceGlobal.SGD_SMS4_CBC;
            case "ECB":
            default:
                return ZaykJceGlobal.SGD_SMS4_ECB;
        }
    }

    private int createSm4Key(final Properties props) {
        ShardingSpherePreconditions.checkState(props.containsKey(KEY_INDEX), () -> new EncryptAlgorithmInitializationException("SM4", String.format("%s can not be null", KEY_INDEX)));
        int result = Integer.parseInt(props.getProperty(KEY_INDEX));
        //todo check key index is exist
//        ShardingSpherePreconditions.checkState(result < 65535, () -> new EncryptAlgorithmInitializationException("SM4", ""));
        return result;
    }

    private byte[] createSm4Iv(final Properties props, final int sm4Mode) {
        if (sm4Mode == ZaykJceGlobal.SGD_SMS4_ECB) {
            return new byte[0];
        }
        ShardingSpherePreconditions.checkState(props.containsKey(IV), () -> new EncryptAlgorithmInitializationException("SM4", String.format("%s can not be null", IV)));
        String sm4IvValue = String.valueOf(props.getProperty(IV));
        byte[] result = fromHexString(sm4IvValue);
        ShardingSpherePreconditions.checkState(IV_LENGTH == result.length, () -> new EncryptAlgorithmInitializationException("SM4", "Iv length must be " + IV_LENGTH + " bytes long"));
        return result;
    }


    @Override
    public Object encrypt(final Object plainValue, AlgorithmSQLContext algorithmSQLContext) {
        return null == plainValue ? null : Hex.encodeHexString(encrypt(String.valueOf(plainValue).getBytes(StandardCharsets.UTF_8)));
    }

    private byte[] encrypt(final byte[] plaintext) {
        return sdf.SDF_Encrypt_Ex(keyIndex, sm4Mode, new byte[0], sm4Iv, plaintext, true);
    }

    @Override
    public Object decrypt(Object plainValue, AlgorithmSQLContext algorithmSQLContext) {
        return null == plainValue ? null : new String(decrypt(fromHexString(String.valueOf(plainValue))), StandardCharsets.UTF_8);
    }

    private byte[] decrypt(final byte[] cipherValue) {
        return sdf.SDF_Decrypt_Ex(keyIndex, sm4Mode, new byte[0], sm4Iv, cipherValue, true);
    }

    @Override
    public String getType() {
        return "SM4-ECB-padding";
    }


    static byte[] fromHexString(final String s) {
        try {
            return Hex.decodeHex(s);
        } catch (final DecoderException ex) {
            throw new EncryptAlgorithmInitializationException("SM", ex.getMessage());
        }
    }
}
