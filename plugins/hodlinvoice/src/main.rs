/*  This is a plugin which adds a "hodlinvoice" 
    command to Core Lightning. 
 */
#[macro_use]
extern crate serde_json;
use rand::Rng;
use cln_plugin::{Builder, Error, Plugin};
use cln_rpc::model::{responses,requests}; 
use tokio;
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let state = ();

/*  
I added other two commands
    cancelinvoice <hash>
    settleinvoice <preimage>
*/

    if let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .rpcmethod("hodlinvoice", 
                   "Call this to create an invoice that will be held until released", 
                   hodlmethod)
        .rpcmethod("settleinvoice", 
                   "Call this to released the preimage", 
                   settlemethod)
        .rpcmethod("cancelinvoice", 
                   "Call this to cancel the invoice", 
                   cancelmethod)
        .hook("htlc_accepted", htlc_accept_handler)
        .start(state)
        .await?
    {
        plugin.join().await
    } else {
        Ok(())
    }
}


/*  
 TODO: what info do we need to pass into hodlinvoice?
 TODO: what should we do with this information?
 nifty guesses: 
     - create an invoice, and remember the preimage/hash 
     
     question: What is the best way to remember the preimage?
               Saving the hash and the preimage in a hashmap maybe?

     - when an htlc with that same preimage/hash is 
     notified in htlc_accept_handler, hold the invoice!
     
     question: But I don't know what response I should return in the htcl_accept_handler method
        {"result": "?"}

    - when do we release the invoice?? 
      
      answer: with a settlemethod 
*/

/*  
example: hodlinvoice <hash> <amount> <label> <expiry>

expiry is optional by default 86400 (24 hours)

We create a preimage and with the parameters  and with the parameters obtained
we use the cln_rpc library to create an invoice

         invoice <amount> <label> <expiry> <preimage>

We must save the invoice <hash> and <preimage> and a boolean field 
 to know if the preimage is retained or not
  
*/

async fn hodlmethod(_p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    
    log::info!("Parametros obtenidos de holdinvoice  {}", _v);

    /* Validate parameters */

    //let _hash: i64 = _v[0].as_i64().unwrap(); 
    //let _amount: i64 = _v[1].as_i64().unwrap();
    //let _label = _v[2].as_str().unwrap();    
    let _expiry: u32=86400;

    /* Create preimage */

    let mut preimage = [0u8; 32];
    rand::thread_rng().fill(&mut preimage[..]);
    
    /*To use cln_rpc to create invoice */

    //let invoice = requests::Invoice::new(amount,label,expiry,preimage);

    /* Save invoice hash  and preimage */
        
    Ok(json!("Return bolt11 invoice"))
    
}

/// Example cancelinvoice <hash>
/// The invoice must be searched with the hash
/// htlc must fail and delete the stored preimage

async fn cancelmethod(_p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> 
{
             
    Ok(json!("htlc must fail and delete the stored preimage"))
    //Ok(json!({"result": "fail","failure_message": "2002"}))
}


/// example: settleinvoice <preimage>
/// The stored preimage is cleared and released

async fn settlemethod(_p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    
    Ok(json!("preimage must be released"))
    //Ok(json!({"result": "resolve","payment_key": preimage }))
}

/// We get htlc but we must retain the preimage.
/// What response should be sent?
async fn htlc_accept_handler(_p: Plugin<()>,v: serde_json::Value,) -> Result<serde_json::Value, Error> {
    log::info!("Got a htlc accepted call: {}", v);
    //The preimage must be retained in order to release it with the settleinvoice command
    Ok(json!({"result": "continue"}))        

}
