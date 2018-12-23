package simplechatserver;

import java.security.InvalidKeyException;
import java.security.UnrecoverableEntryException;

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;

public class ChatClient {
	/**
     * @param args the command line arguments
	 * @throws NoSuchPaddingException 
	 * @throws BadPaddingException 
	 * @throws UnrecoverableEntryException 
	 * @throws InvalidKeyException 
     */
    public static void main(String[] args) throws InvalidKeyException, UnrecoverableEntryException, BadPaddingException, NoSuchPaddingException {
        // Create a new instance of the Chat Server
        SimpleChatClient simpleChatClient = new SimpleChatClient();
        simpleChatClient.run();
    }
}
