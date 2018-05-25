package pl.treekt.xadesandroidtest;

import xades4j.providers.impl.KeyStoreKeyingDataProvider;

import java.security.cert.X509Certificate;

public class DirectPasswordProvider implements KeyStoreKeyingDataProvider.KeyStorePasswordProvider,
        KeyStoreKeyingDataProvider.KeyEntryPasswordProvider {

    private char[] password;

    public DirectPasswordProvider(String password){
        this.password = password.toCharArray();
    }

    @Override
    public char[] getPassword(String entryAlias, X509Certificate entryCert) {
        return password;
    }

    @Override
    public char[] getPassword() {
        return password;
    }
}
