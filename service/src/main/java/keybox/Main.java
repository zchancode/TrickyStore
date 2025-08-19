package keybox;

public class Main {
    public static void main(String[] args) {
        KeystoreInterceptor interceptor = new KeystoreInterceptor();

        boolean res = interceptor.inject();
        if (!res) {
            Logger.i("Failed to inject KeystoreInterceptor, exiting...");
            System.exit(0);
        }

        res = interceptor.readKeyBox();
        if (!res) {
            Logger.i("Failed to read KeyBox, exiting...");
            System.exit(0);
        }

        Logger.i("KeyBox read successfully, starting app...");

        // Keep the application running
        while (true) {
            try {
                Thread.sleep(1000000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Logger.i("Main thread interrupted, exiting...");
                System.exit(0);
            }
        }
    }
}