package com.sinocipher.dbenc.encrypt.sm.algrithm.hard;


import com.zayk.sdf.api.provider.ZaykJceGlobal;
import com.zayk.sdf.api.sdk.ZaykSDF;
import org.junit.jupiter.api.Test;

class SM4PaddingAlgTest {


    @Test
    public  void testInit() {
        SM4PaddingAlg sM4PaddingAlg = new SM4PaddingAlg();
        ZaykSDF sdf = SM4PaddingAlg.getSdf();
        byte[] encData = sdf.SDF_Encrypt_Ex(1, ZaykJceGlobal.SGD_SMS4_ECB, "1234567812345678".getBytes(), null,
                "1234567812345678".getBytes(), false);
        System.out.println(encData.length);
    }

}