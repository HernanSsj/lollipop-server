export interface UserInterface {
    name: String;
    email: string;
    id: string;
  }
  
  export interface DatabaseUserInterface {
    name: String;
    email: string;
    password: string;
    _id: string;
  }

  export interface DatabaseSocialUserInterface {
    name: String;
    socialId: String;
    _id: string;
  }
  export interface SocialUserInterface {
    name: String;
    id: string;
  }
  