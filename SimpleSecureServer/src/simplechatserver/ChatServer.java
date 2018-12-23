package simplechatserver;

import java.security.InvalidKeyException;
import java.security.UnrecoverableEntryException;

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author skiser
 */
public class ChatServer {

    /**
     * @param args the command line arguments
     * @throws UnrecoverableEntryException 
     * @throws NoSuchPaddingException 
     * @throws BadPaddingException 
     * @throws InvalidKeyException 
     */
    public static void main(String[] args) throws InvalidKeyException, BadPaddingException, NoSuchPaddingException, UnrecoverableEntryException {
        // Create a new instance of the Chat Server
        SimpleChatServer simpleChatServer = new SimpleChatServer();
        simpleChatServer.run();
    }
}