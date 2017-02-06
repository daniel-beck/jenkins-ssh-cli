package org.jenkinsci.main.cliclient;

import hudson.cli.NoCheckTrustManager;
import hudson.cli.PrivateKeyProvider;
import hudson.util.QuotedStringTokenizer;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.keyverifier.DefaultKnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.future.WaitableFuture;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseOutputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class App {
    public static void main(String[] args) {
        try {
            _main(args);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
    }

    public static int _main(String[] _args) throws Exception {
        List<String> args = Arrays.asList(_args);
        PrivateKeyProvider provider = new PrivateKeyProvider();
        String username = null;

        String jenkinsUrl = System.getenv("JENKINS_URL");

        if (jenkinsUrl == null)
            jenkinsUrl = System.getenv("HUDSON_URL");

        while (!args.isEmpty()) {
            String head = args.get(0);
            if (head.equals("-version")) {
                printUsage(Messages.CLI_Unsupported_Version());
                return 0;
            }
            if (head.equals("-s") && args.size() >= 2) {
                jenkinsUrl = args.get(1);
                args = args.subList(2, args.size());
                continue;
            }
            if (head.equals("-noCertificateCheck")) {
                System.err.println("Skipping HTTPS certificate checks altogether. Note that this is not secure at all.");
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[]{new NoCheckTrustManager()}, new SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
                // bypass host name check, too.
                HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                    public boolean verify(String s, SSLSession sslSession) {
                        return true;
                    }
                });
                args = args.subList(1, args.size());
                continue;
            }
            if (head.equals("-noKeyAuth")) {
                printUsage(Messages.CLI_Unsupported_NoKeyAuth());
                return -1;
            }
            if (head.equals("-i") && args.size() >= 2) {
                File f = new File(args.get(1));
                if (!f.exists()) {
                    printUsage(Messages.CLI_NoSuchFileExists(f));
                    return -1;
                }

                provider.readFrom(f);

                args = args.subList(2, args.size());
                continue;
            }
            if (head.equals("-p") && args.size() >= 2) {
                printUsage(Messages.CLI_Unsupported_Proxy());
                return -1;
            }
            if (head.equals("-u") && args.size() >= 2) {
                username = args.get(1);
                args = args.subList(2, args.size());
                continue;
            }
            break;
        }

        if (jenkinsUrl == null) {
            printUsage(Messages.CLI_NoURL());
            return -1;
        }

        if (username == null) {
            printUsage(Messages.CLI_NoUsername());
            return -1;
        }

        if (args.isEmpty())
            args = Arrays.asList("help"); // default to help

        if (!provider.hasKeys())
            provider.readFromDefaultLocations();

        URL url = new URL(jenkinsUrl + "/login");
        URLConnection conn = url.openConnection();
        String endpointDescription = conn.getHeaderField("X-SSH-Endpoint");

        if (endpointDescription == null) {
            System.err.println("No header 'X-SSH-Endpoint' returned by Jenkins");
            return -1;
        }

        System.err.println("SSH server is here: " + endpointDescription);

        int sshPort = Integer.valueOf(endpointDescription.split(":")[1]);
        String sshHost = endpointDescription.split(":")[0];

        StringBuilder command = new StringBuilder();

        for (String arg : args) {
            command.append(QuotedStringTokenizer.quote(arg));
            command.append(' ');
        }

        try(SshClient client = SshClient.setUpDefaultClient()) {

            KnownHostsServerKeyVerifier verifier = new DefaultKnownHostsServerKeyVerifier(new ServerKeyVerifier() {
                @Override
                public boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
                    /** unknown key is okay, but log */
                    LOGGER.log(Level.WARNING, "Unknown host key for " + remoteAddress.toString());
                    return true;
                }
            }, true);

            client.setServerKeyVerifier(verifier);
            client.start();

            ConnectFuture cf = client.connect(username, sshHost, sshPort);
            cf.await();
            try (ClientSession session = cf.getSession()) {
                session.addPublicKeyIdentity(provider.getKeys().get(0));
                session.auth().verify(10000L);

                try (ClientChannel channel = session.createExecChannel(command.toString())) {
                    channel.setIn(new NoCloseInputStream(System.in));
                    channel.setOut(new NoCloseOutputStream(System.out));
                    channel.setErr(new NoCloseOutputStream(System.err));
                    WaitableFuture wf = channel.open();
                    wf.await();

                    Set waitMask = channel.waitFor(Collections.singletonList(ClientChannelEvent.CLOSED), 0L);

                    if(waitMask.contains(ClientChannelEvent.TIMEOUT)) {
                        throw new SocketTimeoutException("Failed to retrieve command result in time: " + command);
                    }

                    Integer exitStatus = channel.getExitStatus();
                    return exitStatus;

                }
            } finally {
                client.stop();
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger("hudson.cli.CLI");

    private static void printUsage(String msg) {
        if(msg!=null)   System.out.println(msg);
        System.err.println(Messages.CLI_Usage());
    }
}
