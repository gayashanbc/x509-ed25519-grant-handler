/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.sample.identity.oauth2.grant.ed25519.model.sshj;

import com.hierynomus.sshj.common.KeyAlgorithm;
import com.hierynomus.sshj.signature.Ed25519PublicKey;
import com.hierynomus.sshj.userauth.certificate.Certificate;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Type of key e.g. rsa, dsa */
public enum KeyType {

    /** SSH identifier for RSA keys */
    RSA("ssh-rsa") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            final BigInteger e, n;
            try {
                e = buf.readMPInt();
                n = buf.readMPInt();
            } catch (Buffer.BufferException be) {
                throw new GeneralSecurityException(be);
            }
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyAlgorithm.RSA);
            return keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final RSAPublicKey rsaKey = (RSAPublicKey) pk;
            buf.putMPInt(rsaKey.getPublicExponent()) // e
               .putMPInt(rsaKey.getModulus()); // n
        }

        @Override
        protected boolean isMyType(Key key) {
            return KeyAlgorithm.RSA.equals(key.getAlgorithm());
        }
    },

    ED25519("ssh-ed25519") {
        private final Logger log = LoggerFactory.getLogger(KeyType.class);
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf) throws GeneralSecurityException {
            try {
                final int keyLen = buf.readUInt32AsInt();
                final byte[] p = new byte[keyLen];
                buf.readRawBytes(p);
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Key algo: %s, Key curve: 25519, Key Len: %s\np: %s",
                                            sType,
                                            keyLen,
                                            Arrays.toString(p))
                             );
                }

                EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("Ed25519");
                EdDSAPublicKeySpec publicSpec = new EdDSAPublicKeySpec(p, ed25519);
                return new Ed25519PublicKey(publicSpec);

            } catch (Buffer.BufferException be) {
                throw new SSHRuntimeException(be);
            }
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            EdDSAPublicKey key = (EdDSAPublicKey) pk;
            buf.putBytes(key.getAbyte());
        }

        @Override
        protected boolean isMyType(Key key) {
            return "EdDSA".equals(key.getAlgorithm());
        }
    },

    /** Signed Ed25519 certificate */
    ED25519_CERT("ssh-ed25519-cert-v01@openssh.com") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            return CertUtils.readPubKey(buf, ED25519);
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            CertUtils.writePubKeyContentsIntoBuffer(pk, RSA, buf);
        }

        @Override
        protected boolean isMyType(Key key) {
            return CertUtils.isCertificateOfType(key, RSA);
        }

        @Override
        public KeyType getParent() {
            return RSA;
        }
    },

    /** Signed rsa certificate */
    RSA_CERT("ssh-rsa-cert-v01@openssh.com") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            return CertUtils.readPubKey(buf, RSA);
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            CertUtils.writePubKeyContentsIntoBuffer(pk, RSA, buf);
        }

        @Override
        protected boolean isMyType(Key key) {
            return CertUtils.isCertificateOfType(key, RSA);
        }

        @Override
        public KeyType getParent() {
            return RSA;
        }
    },



    /** Unrecognized */
    UNKNOWN("unknown") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            throw new UnsupportedOperationException("Don't know how to decode key:" + sType);
        }

        @Override
        public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
            throw new UnsupportedOperationException("Don't know how to encode key: " + pk);
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            throw new UnsupportedOperationException("Don't know how to encode key: " + pk);
        }

        @Override
        protected boolean isMyType(Key key) {
            return false;
        }
    };

    protected final String sType;

    private KeyType(String type) {
        this.sType = type;
    }

    public abstract PublicKey readPubKeyFromBuffer(Buffer<?> buf)
            throws GeneralSecurityException;

    protected abstract void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf);

    public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
        writePubKeyContentsIntoBuffer(pk, buf.putString(sType));
    }

    protected abstract boolean isMyType(Key key);

    public static KeyType fromKey(Key key) {
        KeyType result = UNKNOWN;
        for (KeyType kt : values())
            if (kt.isMyType((key)) && (result == UNKNOWN || kt.isSubType(result)))
                result = kt;
        return result;
    }

    private boolean isSubType(KeyType keyType) {
        for (KeyType node = this; node != null; node = node.getParent()) {
            if (keyType == node) {
                return true;
            }
        }
        return false;
    }

    public KeyType getParent() {
        return null;
    }

    public static KeyType fromString(String sType) {
        for (KeyType kt : values())
            if (kt.sType.equals(sType))
                return kt;
        return UNKNOWN;
    }

    @Override
    public String toString() {
        return sType;
    }

    static class CertUtils {

        @SuppressWarnings("unchecked")
        static <T extends PublicKey> Certificate<T> readPubKey(Buffer<?> buf, KeyType innerKeyType) throws GeneralSecurityException {
            Certificate.Builder<T> builder = Certificate.getBuilder();

            try {
                builder.nonce(buf.readBytes());
                builder.publicKey((T) innerKeyType.readPubKeyFromBuffer(buf));
                builder.serial(buf.readUInt64AsBigInteger());
                builder.type(buf.readUInt32());
                builder.id(buf.readString());
                builder.validPrincipals(unpackList(buf.readBytes()));
                builder.validAfter(dateFromEpoch(buf.readUInt64AsBigInteger()));
                builder.validBefore(dateFromEpoch(buf.readUInt64AsBigInteger()));
                builder.critOptions(unpackMap(buf.readBytes()));
                builder.extensions(unpackMap(buf.readBytes()));
                buf.readString(); // reserved
                builder.signatureKey(buf.readBytes());
                builder.signature(buf.readBytes());
            } catch (Buffer.BufferException be) {
                throw new GeneralSecurityException(be);
            }

            return builder.build();
        }

        static void writePubKeyContentsIntoBuffer(PublicKey publicKey, KeyType innerKeyType, Buffer<?> buf) {
            Certificate<PublicKey> certificate = toCertificate(publicKey);
            buf.putBytes(certificate.getNonce());
            innerKeyType.writePubKeyContentsIntoBuffer(certificate.getKey(), buf);
            buf.putUInt64(certificate.getSerial())
               .putUInt32(certificate.getType())
               .putString(certificate.getId())
               .putBytes(packList(certificate.getValidPrincipals()))
               .putUInt64(epochFromDate(certificate.getValidAfter()))
               .putUInt64(epochFromDate(certificate.getValidBefore()))
               .putBytes(packMap(certificate.getCritOptions()))
               .putBytes(packMap(certificate.getExtensions()))
               .putString("") // reserved
               .putBytes(certificate.getSignatureKey())
               .putBytes(certificate.getSignature());
        }

        static boolean isCertificateOfType(Key key, KeyType innerKeyType) {
            if (!(key instanceof Certificate)) {
                return false;
            }
            @SuppressWarnings("unchecked")
            Key innerKey = ((Certificate<PublicKey>) key).getKey();
            return innerKeyType.isMyType(innerKey);
        }

        @SuppressWarnings("unchecked")
        static Certificate<PublicKey> toCertificate(PublicKey key) {
            if (!(key instanceof Certificate)) {
                throw new UnsupportedOperationException("Can't convert non-certificate key " +
                                                        key.getAlgorithm() + " to certificate");
            }
            return ((Certificate<PublicKey>) key);
        }

        private static Date dateFromEpoch(BigInteger seconds) {
            BigInteger maxValue = BigInteger.valueOf(Long.MAX_VALUE / 1000);
            if (seconds.compareTo(maxValue) > 0) {
                return new Date(maxValue.longValue() * 1000);
            } else {
                return new Date(seconds.longValue() * 1000);
            }
        }

        private static BigInteger epochFromDate(Date date) {
            long time = date.getTime() / 1000;
            if (time >= Long.MAX_VALUE / 1000) {
                // Dealing with the signed longs in Java. Since the protocol requires a unix timestamp in milliseconds,
                // and since Java can store numbers not bigger than 2^63-1 as `long`, we can't distinguish dates
                // after `new Date(Long.MAX_VALUE / 1000)`. It's unlikely that someone uses certificate valid until
                // the 10 January of 294247 year. Supposing that such dates are unlimited.
                // OpenSSH expects to see 0xFF_FF_FF_FF_FF_FF_FF_FF in such cases.
                return Buffer.MAX_UINT64_VALUE;
            } else {
                return BigInteger.valueOf(time);
            }
        }

        private static String unpackString(byte[] packedString) throws Buffer.BufferException {
            if (packedString.length == 0) {
                return "";
            }
            return new Buffer.PlainBuffer(packedString).readString();
        }

        private static List<String> unpackList(byte[] packedString) throws Buffer.BufferException {
            List<String> list = new ArrayList<String>();
            Buffer<?> buf = new Buffer.PlainBuffer(packedString);
            while (buf.available() > 0) {
                list.add(buf.readString());
            }
            return list;
        }

        private static Map<String, String> unpackMap(byte[] packedString) throws Buffer.BufferException {
            Map<String, String> map = new LinkedHashMap<String, String>();
            Buffer<?> buf = new Buffer.PlainBuffer(packedString);
            while (buf.available() > 0) {
                String name = buf.readString();
                String data = unpackString(buf.readStringAsBytes());
                map.put(name, data);
            }
            return map;
        }

        private static byte[] packString(String data) {
            if (data == null || data.isEmpty()) {
                return "".getBytes();
            }
            return new Buffer.PlainBuffer().putString(data).getCompactData();
        }

        private static byte[] packList(Iterable<String> strings) {
            Buffer<?> buf = new Buffer.PlainBuffer();
            for (String string : strings) {
                buf.putString(string);
            }
            return buf.getCompactData();
        }

        private static byte[] packMap(Map<String, String> map) {
            Buffer<?> buf = new Buffer.PlainBuffer();
            List<String> keys = new ArrayList<String>(map.keySet());
            Collections.sort(keys);
            for (String key : keys) {
                buf.putString(key);
                String value = map.get(key);
                buf.putString(packString(value));
            }
            return buf.getCompactData();
        }
    }
}
