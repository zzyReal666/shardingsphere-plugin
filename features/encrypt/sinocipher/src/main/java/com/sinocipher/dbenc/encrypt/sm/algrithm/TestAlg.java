package com.sinocipher.dbenc.encrypt.sm.algrithm;

import lombok.Getter;
import org.apache.shardingsphere.encrypt.spi.EncryptAlgorithm;
import org.apache.shardingsphere.encrypt.spi.EncryptAlgorithmMetaData;
import org.apache.shardingsphere.infra.algorithm.core.context.AlgorithmSQLContext;

import java.util.Properties;

/**
 * @author zzypersonally@gmail.com
 * @description
 * @since 2024/5/27 15:12
 */
public class TestAlg implements EncryptAlgorithm {


    @Getter
    private final EncryptAlgorithmMetaData metaData = new EncryptAlgorithmMetaData(true, false, false, new Properties());

    @Override
    public String getType() {
        return "TestAlg";
    }



    @Override
    public String encrypt(Object o, AlgorithmSQLContext algorithmSQLContext) {
        return o+":encrypt";
    }

    @Override
    public String decrypt(Object o, AlgorithmSQLContext algorithmSQLContext) {
        String[] split = String.valueOf(o).split(":");
        return split[0];
    }


}
