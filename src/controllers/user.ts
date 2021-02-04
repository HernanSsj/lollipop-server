export const getUser = ()=> (req: any, res: any) => {
  
    if(req.user){
      res.json(req.user);
    }else{
      res.json(null)
    }
    
    
  }