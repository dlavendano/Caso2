import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.generator.ClientServerTask;

public class Generator {

	
	/**
	 * Load Generator Service (From GLoad 1.0)
	 */
	private LoadGenerator generator;
	
	/**
	 * Constructs a new Generator
	 */
	public Generator(){
		Task work = createTask();
		int numberOfTasks = 100;
		int gapBetweenTasks = 1000;
		generator = new LoadGenerator("Client - Server Load Test", numberOfTasks, work, gapBetweenTasks);
	}
	
	/**
	 * Helper that Constructs a Task
	 */
	private Task createTask(){
		return new ClientServerTask();
	}

}
