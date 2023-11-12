package burp;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.util.regex.Matcher;

import org.yaml.snakeyaml.Yaml;

import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JMenuItem;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import org.yaml.snakeyaml.DumperOptions;

public class BurpExtender implements IBurpExtender,IHttpListener, IContextMenuFactory{
	
	String matcher = null;
	IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
    List<RepeateAndReplace> repeateAndReplaces = new ArrayList<RepeateAndReplace>();
    Tab tab;
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
    	Locale.setDefault(new Locale("en"));
    	
    	callbacks.setExtensionName("Repeate And Replace");
    	this.stdout = new PrintWriter(callbacks.getStdout(), true);
    	this.stdout.println("Repeate And Replace v1.0");
    	this.stdout.println("Author: WhileEndless");
    	this.stdout.println("GITHUB: https://github.com/WhileEndless");
    	this.stdout.println("LINKEDIN: https://www.linkedin.com/in/ahmetcan-akçay-b88379163/");
    	
        this.helpers = callbacks.getHelpers();
        callbacks.registerHttpListener(this);
        this.callbacks=callbacks;
        this.tab = new Tab(callbacks);
        this.tab.reloadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
            	repeateAndReplaces.clear();
            	for (int row = 0; row < tab.model.getRowCount(); row++) {
            		if ((Boolean) tab.model.getValueAt(row, 0)) {
	            		repeateAndReplaces.add(new RepeateAndReplace(tab.model.getValueAt(row, 2).toString(),stdout));
	            		tab.model.setValueAt(repeateAndReplaces.get(repeateAndReplaces.size()-1).name, row, 1);
            		}
            	}
            }
        });
        callbacks.addSuiteTab(this.tab);
        callbacks.registerContextMenuFactory(this);
  }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {//gidiş //enc yapılacak yer burası
    	if (toolFlag ==IBurpExtenderCallbacks.TOOL_EXTENDER) {
    		return;
    	}
    	
    	if (messageIsRequest) {
    		IRequestInfo reqInfo = this.helpers.analyzeRequest(messageInfo);
    		String request = new String(messageInfo.getRequest());
    		String requestHeaders = reqInfo.getHeaders().stream()
                    .collect(Collectors.joining("\n"));
    		
            String requestBody = request.substring(reqInfo.getBodyOffset());
            for (RepeateAndReplace repeateAndReplace:this.repeateAndReplaces) {
            	repeateAndReplace.checkAndRun(this.callbacks,messageInfo, toolFlag, requestHeaders, requestBody);
            }
    		return;
    	}
    	IRequestInfo reqInfo = this.helpers.analyzeRequest(messageInfo);
		String request = new String(messageInfo.getRequest());
		String requestHeaders = reqInfo.getHeaders().stream()
                .collect(Collectors.joining("\n"));
		
        String requestBody = request.substring(reqInfo.getBodyOffset());
        IResponseInfo resInfo = this.helpers.analyzeResponse(messageInfo.getResponse());
        String response = new String(messageInfo.getResponse());
        String responseHeaders = resInfo.getHeaders().stream()
                .collect(Collectors.joining("\n"));
        String responseBody = response.substring(resInfo.getBodyOffset());
        for (RepeateAndReplace repeateAndReplace:this.repeateAndReplaces) {
        	repeateAndReplace.checkAndRun(callbacks,messageInfo,toolFlag ,messageInfo.getHttpService(),requestHeaders,requestBody,responseHeaders,responseBody);
        }
    }
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    	List<JMenuItem> menuItems = new ArrayList<>();
        JMenuItem sendToFunctionMenuItem1 = new JMenuItem("Copy As Repeat");
        sendToFunctionMenuItem1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] selectedRequests = invocation.getSelectedMessages();
                IRequestInfo requestInfo = helpers.analyzeRequest(selectedRequests[0]);
                byte[] requestBytes = selectedRequests[0].getRequest();
                String request = new String(requestBytes);
                Map<String, Object> service = new HashMap<>();
                service.put("host", selectedRequests[0].getHost());
                service.put("port", selectedRequests[0].getPort());
                service.put("protocol", selectedRequests[0].getProtocol());

                List<String> rawRequests = new ArrayList<>();
                rawRequests.add(request);

                List<Map<String, Object>> yamlList = new ArrayList<>();
                Map<String, Object> yamlMap = new HashMap<>();
                yamlMap.put("service", service);
                yamlMap.put("raw_request", rawRequests);
                yamlList.add(yamlMap);

                DumperOptions options = new DumperOptions();
                options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                options.setPrettyFlow(true);

                Yaml yaml = new Yaml(options);
                String output = yaml.dump(yamlList);
                copyToClipboard(output);

            }
        });
        menuItems.add(sendToFunctionMenuItem1);
        
        
        
        
        return menuItems;
    }
    public static void copyToClipboard(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable transferable = new StringSelection(text);
        clipboard.setContents(transferable, null);
    }
}



class Matchers{
	enum Locations{
		request_header,
		request_body,
		response_header,
		response_body
	}
	class Matcher{
		public Locations from;
		public List<String> contains;
		Boolean regex;
		
		public Matcher(Locations from, List<String> contains,Boolean regex) {
			this.from=from;
			this.contains=contains;
			this.regex=regex;
		}
		public Boolean check(String requestHeader,String requestBody) {

			String serchArea = null;
			if (from==Locations.request_header) {
				serchArea=requestHeader;
			}else if (from==Locations.request_body) {
				serchArea=requestBody;
			}
			else {
				System.out.println("'"+from+"' key not found!");
				return false;
			}
			for (String contain: contains) {
				if (!regex) {
					if (!serchArea.contains(contain)) {
						return false;
					}
					continue;
				}
				Pattern pattern = Pattern.compile(contain);
				if (!pattern.matcher(serchArea).find()) {
					return false;
				}
			}
			return true;
		}
		public Boolean check(String requestHeader,String requestBody,String responseHeader, String responseBody,Boolean continuousupdate) {
			String serchArea = null;
			if (from==Locations.request_header && continuousupdate==false) {
				serchArea=requestHeader;
			}else if(from==Locations.request_body&& continuousupdate==false) {
				serchArea=requestBody;
			}else if(from==Locations.response_header) {
				serchArea=responseHeader;
			}else if(from==Locations.response_body) {
				serchArea=responseBody;
			}else {
				return false;
			}
			for (String contain: contains) {
				if (!regex) {
					if (!serchArea.contains(contain)) {
						return false;
					}
					continue;
				}
				Pattern pattern = Pattern.compile(contain);
				if (!pattern.matcher(serchArea).find()) {
					return false;
				}
			}
			return true;
		}
	}
	private List<Matcher> matchers;
	private Boolean checkResponse;
	public Matchers(List<Map<String, Object>> matchers) {
		this.checkResponse=false;
		this.matchers = new ArrayList<Matcher>();
		for (Map<String, Object> m: matchers) {
			Locations from = Locations.valueOf((String) m.get("from"));
			if (from==Locations.response_header||from==Locations.response_body) {
				this.checkResponse=true;
			}
			List<String> contains = (List<String>) m.get("contains");
			Boolean regex;
			if (m.containsKey("regex")) {
				regex = (Boolean) m.get("regex");
			}else {
				regex=false;
			}
			Matcher match = new Matcher(from,contains,regex);
			this.matchers.add(match);
		}
	}
	public Boolean check(String requestHeader,String requestBody) {
		if (checkResponse) {
			return false;
		}
		for (Matcher matcher: this.matchers) {
			if (!matcher.check(requestHeader, requestBody)) {
				return false;
			}
		}
		return true;
	}
	public Boolean check(String requestHeader,String requestBody,String responseHeader, String responseBody,Boolean continuousupdate) {
		for (Matcher matcher: this.matchers) {
			if (!matcher.check(requestHeader, requestBody,responseHeader,responseBody,continuousupdate)) {
				return false;
			}
		}
		return true;
	}
	public static List<Matchers> generate(Map<String, Object> yamlData,int flag){
		List<Matchers> matchers= new ArrayList<Matchers>();
		List<List<Map<String, Object>>> matcher = null;
		if (flag==0) {
			matcher = (List<List<Map<String, Object>>>) yamlData.get("matcher");
			
			
		}
		else if (flag==1) {//request
			Map<String, Object> yamlData2 = (Map<String, Object>) yamlData.get("matcher");
			matcher = (List<List<Map<String, Object>>>) yamlData2.get("request");
		}else if (flag==2) {
			Map<String, Object> yamlData2 = (Map<String, Object>) yamlData.get("matcher");
			matcher = (List<List<Map<String, Object>>>) yamlData2.get("response");
		}else {
			return null;
		}
		for (List<Map<String, Object>> list : matcher) {
			Matchers m=new Matchers(list);
			matchers.add(m);
		}

		return matchers;
	}
	
}

enum From{
	Repeater(IBurpExtenderCallbacks.TOOL_REPEATER),
	Scanner(IBurpExtenderCallbacks.TOOL_SCANNER),
	Proxy(IBurpExtenderCallbacks.TOOL_PROXY),
	Intruder(IBurpExtenderCallbacks.TOOL_INTRUDER);
	
	private final int id;

    private From(int id) {
        this.id = id;
    }
    public int getID() {
        return id;
    }
}

class Repeate{
	class Requets{
		
		class Service{
			private String host;
			private int port;
			private String protocol;
			public Service(String host, int port, String protocol) {
				this.host=host;
				this.port=port;
				this.protocol=protocol;
			}
			public IHttpService Build(IExtensionHelpers helpers){
				return helpers.buildHttpService(host, port, protocol);
			}
		}
		class Extractor{
			private String name;
			private String start;
			private String end;
			private Boolean regex;
			
			public Extractor(String name,String start,String end,Boolean regex) {
				this.name=name;
				this.start=start;
				this.end=end;
				this.regex=regex;
			}
			public String extract(String response) {
				int startIndex=-1;
				if (!regex) {
			        startIndex = response.indexOf(this.start);
				}else {
					Pattern pattern = Pattern.compile(this.start);
			        Matcher matcher = pattern.matcher(response);
			        if (matcher.find()) {
			        	startIndex=matcher.end();
			        }
				}
			        
		        if (startIndex == -1) {
		            return null;
		        }
		        String cutedResponse=null;
		        if (!regex) {
		        	cutedResponse = response.substring(startIndex + this.start.length());
		        }
		        else {
		        	cutedResponse = response.substring(startIndex);
		        }
		        
		        if (this.end=="") {
		        	return cutedResponse;
		        }
		        int endIndex=-1;
		        if (!regex) {
		        	endIndex = cutedResponse.indexOf(this.end);
		        }else {
		        	Pattern pattern = Pattern.compile(this.end);
			        Matcher matcher = pattern.matcher(cutedResponse);
			        if (matcher.find()) {
			        	endIndex=matcher.start();
			        }
		        }
		        if (endIndex == -1) {
		            return null;
		        }
		        return cutedResponse.substring(0, endIndex);
		    }
		}
		class Replacer{
			private String replace_with;
			private String start;
			private String end;
			private Boolean regex;
			
			public Replacer(String replace_with,String start,String end,Boolean regex) {
				this.replace_with=replace_with;
				this.start=start;
				this.end=end;
				this.regex=regex;
			}
			public String replace(String request,Map<String,String> replaceWith) {
				int startIndex = -1; 
				if (!this.regex) {
					startIndex = request.indexOf(this.start);
				}else {
					Pattern pattern = Pattern.compile(this.start);
			        Matcher matcher = pattern.matcher(request);
			        if (matcher.find()) {
			        	startIndex=matcher.end();
			        }
				}
				if (startIndex == -1) {
		            return request;
		        }
				
				String cutedRequest=null;
		        if (!regex) {
		        	cutedRequest = request.substring(startIndex + this.start.length());
		        }
		        else {
		        	cutedRequest = request.substring(startIndex);
		        }
		        String beforStart=null;
		        if (!regex) {
		        	beforStart = request.substring(0, startIndex+this.start.length());
		        }else {
		        	beforStart = request.substring(0, startIndex);
		        }
		        if (this.end=="") {
					return beforStart+replaceWith.get(this.replace_with);
				}
		        int endIndex=-1;
		        if (!regex) {
		        	endIndex = cutedRequest.indexOf(this.end);
		        }else {
		        	Pattern pattern = Pattern.compile(this.end);
			        Matcher matcher = pattern.matcher(cutedRequest);
			        if (matcher.find()) {
			        	endIndex=matcher.start();
			        }

		        }
		        
				if (endIndex == -1) {
		            return request;
		        }
				
				
		        String afetEnd = cutedRequest.substring(endIndex);
				return beforStart+replaceWith.get(this.replace_with)+afetEnd;
		    }
		}
		private Service service;
		private String raw_request;
		private List<Extractor> extractors = new ArrayList<Repeate.Requets.Extractor>();
		private List<Replacer> replacers = new ArrayList<Repeate.Requets.Replacer>();
		private PrintWriter stdout;
		public Requets(Map<String, Object> yamlData,PrintWriter stdout) {
			this.stdout = stdout;
			
			
			Map<String, Object> yservice = (Map<String, Object>) yamlData.get("service");
			if (yservice==null) {
				this.stdout.println("service Key Not Found");
			}
			this.service = new Service((String)yservice.get("host"), (int) yservice.get("port"), (String)yservice.get("protocol"));
			this.raw_request = ((Collection<String>) yamlData.get("raw_request")).stream().collect(Collectors.joining("\r\n")); // Boşlukla ayrılmış birleştirme

			List<Map<String, Object>> yextractors = (List<Map<String, Object>>) yamlData.get("extractor");
			if (yextractors!=null) {
				for (Map<String, Object> yextractor: yextractors) {
					Boolean regex=false;
					if (yextractor.containsKey("regex")) {
						regex= (Boolean) yextractor.get("regex");
					}
					this.extractors.add(new Extractor((String) yextractor.get("name"), (String) yextractor.get("start"), (String) yextractor.get("end"),regex));
				}
			}
			List<Map<String, Object>> yreplacers = (List<Map<String, Object>>) yamlData.get("replacer");
			if (yreplacers!=null) {
				for (Map<String, Object> yreplacer: yreplacers) {
					Boolean regex=false;
					if (yreplacer.containsKey("regex")) {
						regex= (Boolean) yreplacer.get("regex");
					}
					this.replacers.add(new Replacer((String) yreplacer.get("replace_with"), (String) yreplacer.get("start"), (String) yreplacer.get("end"),regex));
				}
			}
			this.stdout.println("Request loaded successfully");
		}
		public void makeRequest( Map<String,String> replaceValues,IBurpExtenderCallbacks callbacks) {
			this.stdout.println("Request is repeating");
			String request = this.raw_request;
			for (Replacer replacer: this.replacers) {
				request = replacer.replace(request, replaceValues);
			}
			request+="\r\n\r\n";
			IHttpRequestResponse responseobj = callbacks.makeHttpRequest(this.service.Build(callbacks.getHelpers()),request.getBytes());
			String response = new String(responseobj.getResponse());
			
			for (Extractor extractor: this.extractors) {
				String data = extractor.extract(response);
				if (data!=null) {
					this.stdout.println("Extracted data | '"+extractor.name+"':'"+data+"'");
					replaceValues.put(extractor.name, data) ;
				}
				else {
					this.stdout.println("Data Extraction error | '"+extractor.name+"'");
				}
				
			}
		}
	}
	List<Requets> requests = new ArrayList<Repeate.Requets>();
	Map<String,String> replaceValues = new HashMap<String, String>();
	private PrintWriter stdout;
	public Repeate(Map<String, Object> yamlData,PrintWriter stdout) {
		this.stdout = stdout;
		List<Map<String,Object>> repetes = (List<Map<String,Object>>) yamlData.get("repeat");
		if (repetes==null) {
			this.stdout.println("repeat Key Not Found");
		}
		for (Map<String,Object> repeat: repetes) {
			requests.add(new Requets(repeat,this.stdout));
		}
	}
	public void run(IBurpExtenderCallbacks callbacks) {
		for (Requets request: this.requests) {
			request.makeRequest(this.replaceValues,callbacks);
		}
	}
}



class RepeateAndReplace{
	List<Matchers> matchers;
	List<Matchers> request_matchers;
	Repeate repeate;
	private Boolean continuousupdate=false;
	private List<Replacer> replacers = new ArrayList<RepeateAndReplace.Replacer>();
	private PrintWriter stdout;
	private Boolean first=true;
	private List<Integer> from = new ArrayList<Integer>();
	class Replacer{
		private String replace_with;
		private String start;
		private String end;
		private Boolean regex;
		
		public Replacer(String replace_with,String start,String end,Boolean regex) {
			this.replace_with=replace_with;
			this.start=start;
			this.end=end;
			this.regex=regex;
		}
		public String replace(String request,Map<String,String> replaceWith) {
			int startIndex = -1; 
			if (!this.regex) {
				startIndex = request.indexOf(this.start);
			}else {
				Pattern pattern = Pattern.compile(this.start);
		        Matcher matcher = pattern.matcher(request);
		        if (matcher.find()) {
		        	startIndex=matcher.end();
		        }
			}
			if (startIndex == -1) {
	            return request;
	        }
			
			String cutedRequest=null;
	        if (!regex) {
	        	cutedRequest = request.substring(startIndex + this.start.length());
	        }
	        else {
	        	cutedRequest = request.substring(startIndex);
	        }
	        String beforStart=null;
	        if (!regex) {
	        	beforStart = request.substring(0, startIndex+this.start.length());
	        }else {
	        	beforStart = request.substring(0, startIndex);
	        }
	        if (this.end=="") {
				return beforStart+replaceWith.get(this.replace_with);
			}
	        int endIndex=-1;
	        if (!regex) {
	        	endIndex = cutedRequest.indexOf(this.end);
	        }else {
	        	Pattern pattern = Pattern.compile(this.end);
		        Matcher matcher = pattern.matcher(cutedRequest);
		        if (matcher.find()) {
		        	endIndex=matcher.start();
		        }

	        }
	        
			if (endIndex == -1) {
	            return request;
	        }
			
			
	        String afetEnd = cutedRequest.substring(endIndex);
			return beforStart+replaceWith.get(this.replace_with)+afetEnd;
	    }
	}
	public String name;
	
	public RepeateAndReplace(String path,PrintWriter stdout) {
		this.stdout = stdout;
		try (InputStream input = new FileInputStream(path)) {
			Yaml yaml = new Yaml();
            Map<String, Object> yamlData = yaml.load(input);
            this.continuousupdate = (Boolean)yamlData.get("continuousupdate");
            this.repeate = new Repeate(yamlData,this.stdout);
            if (this.continuousupdate) {
            	this.request_matchers=Matchers.generate(yamlData, 1);
            	if (this.request_matchers==null) {
            		this.stdout.println("Error. If continuousupdate is set to true, request and response assignments must be made separately.");
            	}
            	this.matchers=Matchers.generate(yamlData, 2);
            	if (this.matchers==null) {
            		this.stdout.println("Error. If continuousupdate is set to true, request and response assignments must be made separately.");
            	}
            }else {
            	this.matchers = Matchers.generate(yamlData,0);
            }
            this.name= (String) yamlData.get("name");
            List<Map<String, Object>> yreplacers = (List<Map<String, Object>>) yamlData.get("replacer");
			for (Map<String, Object> yreplacer: yreplacers) {
				Boolean regex=false;
				if (yreplacer.containsKey("regex")) {
					regex= (Boolean) yreplacer.get("regex");
				}
				this.replacers.add(new Replacer((String) yreplacer.get("replace_with"), (String) yreplacer.get("start"), (String) yreplacer.get("end"),regex));
			}
			Boolean continuousupdate = (Boolean)yamlData.get("continuousupdate");
			if (continuousupdate!=null) {
				this.continuousupdate=continuousupdate;
			}
			
			
			for (String from: (List<String>)yamlData.get("from")) {
				try {
					this.from.add(From.valueOf(from).getID());
				}
				catch (IllegalArgumentException e){
					this.stdout.println("From key not found | From: "+from);
				}
			}
			
			this.stdout.println("'"+path+"' file successfully loaded.");
        } catch (IOException e) {
            e.printStackTrace(this.stdout);
        }
	}
	public void checkAndRun(IBurpExtenderCallbacks callbacks,IHttpRequestResponse messageInfo,int toolFlag,String requestHeaders,String requestBody) {
		if (!this.from.contains(toolFlag)) {return;}
        Boolean f=false;
        if (this.continuousupdate && this.first==false) {
        	for (Matchers m: this.request_matchers) {
        		this.stdout.println("Match found12");
    			for (Replacer replace: this.replacers) {
    	        	this.stdout.println(requestBody);
    	        	requestBody=replace.replace(requestBody, this.repeate.replaceValues);
    	        	this.stdout.println(requestBody);
    	        	requestHeaders=replace.replace(requestHeaders, this.repeate.replaceValues);
    	        }
    			List<String> headers = Stream.of(requestHeaders.split("\n")).collect(Collectors.toList());
    	        byte[] body = requestBody.getBytes();
    	        messageInfo.setRequest(callbacks.getHelpers().buildHttpMessage(headers, body));
    	        return;
        	}
        }else if (this.continuousupdate){
        	this.first=false;
        }else{
			for (Matchers m: this.matchers) {
	        	if (m.check(requestHeaders, requestBody)) {
	        		this.stdout.println("Match found");
	        		f=true;
	        		repeate.run(callbacks);
	        		this.first=false;
	        		break;
	        	}
	        }
		}
		if (!f) {
			return;
		}
        for (Replacer replace: this.replacers) {
        	this.stdout.println(requestBody);
        	requestBody=replace.replace(requestBody, this.repeate.replaceValues);
        	this.stdout.println(requestBody);
        	requestHeaders=replace.replace(requestHeaders, this.repeate.replaceValues);
        }
        List<String> headers = Stream.of(requestHeaders.split("\n")).collect(Collectors.toList());
        byte[] body = requestBody.getBytes();
        messageInfo.setRequest(callbacks.getHelpers().buildHttpMessage(headers, body));
	}
	public void checkAndRun(IBurpExtenderCallbacks callbacks,IHttpRequestResponse messageInfo,int toolFlag, IHttpService service,String requestHeaders,String requestBody, String responseHeader, String responseBody) {
		if (!this.from.contains(toolFlag)) {return;}
		Boolean f=false;
		for (Matchers m: this.matchers) {
        	if (m.check(requestHeaders, requestBody,responseHeader, responseBody,this.continuousupdate)) {
        		this.stdout.println("Match found");
        		repeate.run(callbacks);
        		f=true;
        		break;
        	}
        }
		if (!f) {
			return;
		}
        for (Replacer replace: this.replacers) {
        	requestBody=replace.replace(requestBody, this.repeate.replaceValues);
        	requestHeaders=replace.replace(requestHeaders, this.repeate.replaceValues);
        }
        for (Replacer replace: this.replacers) {
        	requestBody=replace.replace(requestBody, this.repeate.replaceValues);
        	requestHeaders=replace.replace(requestHeaders, this.repeate.replaceValues);
        }
        List<String> headers = Stream.of(requestHeaders.split("\n")).collect(Collectors.toList());
        byte[] body = requestBody.getBytes();
        IHttpRequestResponse responseobj = callbacks.makeHttpRequest(service,callbacks.getHelpers().buildHttpMessage(headers, body));
        messageInfo.setResponse(responseobj.getResponse());
	}
}