package treekt.pl.xadesandroidtest;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.afollestad.materialdialogs.MaterialDialog;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import xades4j.XAdES4jException;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.SigningKeyException;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.UnexpectedJCAException;

public class MainActivity extends AppCompatActivity {


    private static final int READ_REQUEST_CODE_DOC = 42;
    private static final int READ_REQUEST_CODE_CERT = 41;
    private static String documentPath;
    private static String certificatePath;
    private static String certificatePassword;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onChooseDocument(View view) {
        Toast.makeText(getApplicationContext(), "Select document", Toast.LENGTH_SHORT).show();
        performDocumentSearch();
    }

    public void onChooseCertificate(View view) {
        Toast.makeText(getApplicationContext(), "Select certificate", Toast.LENGTH_SHORT).show();
        performCertificateSearch();
    }

    public void signDocumentOnClick(View view) {
        try{
            XadesSigner signer = getSigner(certificatePath, certificatePassword);
            signWithoutIDEnveloped(documentPath, this.getFilesDir().toString() + "/signedDocument.xml", signer);
            TextView signingStatusTextView = findViewById(R.id.signingStatusTextView);
            signingStatusTextView.setText("Document has been signed and save in " + this.getFilesDir().toString() + "/signedDocument.xml");
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    private void performDocumentSearch() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/xml");
        startActivityForResult(intent, READ_REQUEST_CODE_DOC);
    }

    private void performCertificateSearch() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/x-pkcs12");

        startActivityForResult(intent, READ_REQUEST_CODE_CERT);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode,
                                 Intent resultData) {

        if ((requestCode == READ_REQUEST_CODE_DOC || requestCode == READ_REQUEST_CODE_CERT) && resultCode == Activity.RESULT_OK) {

            Uri uri;
            String path;
            if (resultData != null) {
                uri = resultData.getData();
                try {
                    path = PathUtil.getPath(this, uri);
                    Toast.makeText(getApplicationContext(), path, Toast.LENGTH_SHORT).show();
                    if(requestCode == READ_REQUEST_CODE_DOC){
                        documentPath = path;
                        TextView chooseDocumentTextView = findViewById(R.id.chooseDocumentTextView);
                        chooseDocumentTextView.setText(R.string.document_selected);
                    }else{
                        certificatePath = path;
                        TextView chooseDocumentTextView = findViewById(R.id.chooseCertificateTextView);
                        chooseDocumentTextView.setText(R.string.certificate_selected);
                        MaterialDialog.Builder builder = new MaterialDialog.Builder(this).title("Certificate password").content("Enter the password for the certificate.");
                        Dialog passwordDialog = builder
                                .inputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD)
                                .input(R.string.type_password, 0, new MaterialDialog.InputCallback() {
                                    @Override
                                    public void onInput(MaterialDialog dialog, CharSequence input) {
                                        certificatePassword = input.toString();
                                        TextView typePasswordTextView = findViewById(R.id.typePasswordTextView);
                                        typePasswordTextView.setText(R.string.password_entered);
                                    }
                                }).show();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

    }

    /**
     * Tworzy i zwraca obiekt podpisujacego Signer
     *
     * @param pfxPath  Sciezka certyfikatu
     * @param password Haslo certyfikatu
     * @return Obiekt podpisujacego Signer
     * @throws SigningKeyException
     */
    public static XadesSigner getSigner(String pfxPath, String password) throws SigningKeyException {

        try {
            KeyingDataProvider keyingProvider = getKeyingDataProvider(pfxPath, password);
            XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
            return p.newSigner();

        } catch (KeyStoreException ex) {
            throw new SigningKeyException("Keystore Problem", ex);
        } catch (SigningCertChainException ex) {
            throw new SigningKeyException("Signer Cert Chain Problem", ex);
        } catch (UnexpectedJCAException ex) {
            throw new SigningKeyException("JCA Problem", ex);
        } catch (XadesProfileResolutionException ex) {
            throw new SigningKeyException("XadesProfileResolutionException Problem", ex);
        }
    }

    /**
     * Tworzy i zwraca obiekt KeyingDataProvider
     *
     * @param pfxPath  Sciezka certyfikatu
     * @param password Haslo certyfikatu
     * @return Obiekt KeyingDataProvider
     * @throws KeyStoreException
     * @throws SigningCertChainException
     * @throws UnexpectedJCAException
     */
    private static KeyingDataProvider getKeyingDataProvider(String pfxPath, String password) throws KeyStoreException, SigningCertChainException, UnexpectedJCAException {

        KeyingDataProvider keyingProvider = new FileSystemKeyStoreKeyingDataProvider(
                "pkcs12",
                pfxPath,
                new FirstCertificateSelector(),
                new DirectPasswordProvider(password),
                new DirectPasswordProvider(password),
                true);

        if (keyingProvider.getSigningCertificateChain().isEmpty()) {
            throw new IllegalArgumentException("Nie mozna zainicializowac magazynu kluczy ze sciezki: " + pfxPath);
        }

        return keyingProvider;
    }


    /**
     * Tworzy podpis i podpisuje nim dokument uzywając struktury kopertowej (enveloped structure)
     * Metoda podpisuje wezel głowny, nie zawierajacy ID
     *
     * @param inputPath  Sciezka dokumentu XML do podpisu
     * @param outputPath Sciezka dla podpisanego dokumentu XML
     * @param signer
     * @throws TransformerFactoryConfigurationError
     * @throws XAdES4jException
     * @throws TransformerException
     * @throws IOException
     **/
    private static void signWithoutIDEnveloped(String inputPath, String outputPath, XadesSigner signer) throws TransformerFactoryConfigurationError, XAdES4jException, TransformerException, IOException {


        Document sourceDoc = getDocument(inputPath);
        sourceDoc.setDocumentURI(null);

        writeXMLToFile(sourceDoc, outputPath);

        sourceDoc = getDocument(outputPath);

        Element signatureParent = sourceDoc.getDocumentElement();
        Element elementToSign = sourceDoc.getDocumentElement();
        String refUri;
        if (elementToSign.hasAttribute("Id"))
            refUri = '#' + elementToSign.getAttribute("Id");
        else {
            if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE)
                throw new IllegalArgumentException("Element bez identyfikatora, musi byc glownym wezlem");
            refUri = "";
        }

        DataObjectDesc dataObjRef = new DataObjectReference(refUri).withTransform(new GenericAlgorithm(Transforms.TRANSFORM_ENVELOPED_SIGNATURE));
        SignedDataObjects signedDataObjects = new SignedDataObjects(dataObjRef);
        signer.sign(signedDataObjects, signatureParent);


        writeXMLToFile(sourceDoc, outputPath);
    }


    /**
     * Zapisuje dokument XML do pliku
     *
     * @param doc        Dokument
     * @param outputPath Sciezka do zapisu dokumentu XML
     * @throws TransformerFactoryConfigurationError
     * @throws TransformerException
     * @throws IOException
     **/
    private static void writeXMLToFile(Document doc, String outputPath) throws TransformerFactoryConfigurationError, TransformerException, IOException {
        Source source = new DOMSource(doc);

        File outFile = new File(outputPath);
        outFile.getParentFile().mkdirs();
        outFile.createNewFile();
        FileOutputStream fos = new FileOutputStream(outFile);

        StreamResult result = new StreamResult(fos);

        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        xformer.transform(source, result);

        fos.close();
    }


    /**
     * Pobiera dokument z pliku XML
     *
     * @param path Sciezka do pobrania dokumentu XML
     * @return Dokument pobrany z pliku
     */
    private static Document getDocument(String path) {
        try {
            File fXmlFile = new File(path);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setNamespaceAware(true);
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(fXmlFile);
            doc.getDocumentElement().normalize();
            return doc;
        } catch (SAXException ex) {
            ex.printStackTrace();
            return null;
        } catch (IOException ex) {
            return null;
        } catch (ParserConfigurationException ex) {
            return null;
        }
    }


}
