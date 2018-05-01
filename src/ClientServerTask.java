import java.io.IOException;

import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.Client;

public class ClientServerTask extends Task {
	
	@Override
	public void fail() {
		// TODO Auto-generated method stub
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		// TODO Auto-generated method stub
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() {	
			Client cliente = new Client();
			cliente.sendMessageToServer("hola, soy el cliente");
			cliente.waitForMessageFromServer();
			System.out.println("Error al crear cliente");
		}
}
