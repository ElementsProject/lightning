Draft version of the JLightning rpc interface for c-lightning.

Using this client library is is as simple as the following code:
```
public static void main(String[] args) {
	JLightningRpc rpc_interface = new JLightningRpc("/tmp/spark-env/ln1/lightning-rpc");
	String res = rpc_interface.listInvoices(null);
	System.out.println(res);
	res = rpc_interface.listFunds();
	System.out.println(res);
}
```

This client library is provided and maintained by Rene Pickhardt