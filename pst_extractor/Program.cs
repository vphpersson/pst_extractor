using System.Collections.Generic;
using System.Linq;
using System;
using System.Security.Cryptography;  
using System.IO;

using PSTParse;
using PSTParse.MessageLayer;
using HtmlAgilityPack;
using Newtonsoft.Json;


namespace pst_extractor {

    public struct AttachmentInfo {
        public string filename;
        public string sha256_hash;

        public AttachmentInfo(string filename, string sha256_hash) {
            this.filename = filename;
            this.sha256_hash = sha256_hash;
        }
    }
    
    public struct MessageInfo {
        public string folder_name;
        public string sender_address;
        public DateTime created_date;
        public DateTime received_date;
        public List<string> to_addresses;
        public List<string> cc_addresses;
        public List<string> bcc_addresses;
        
        public List<AttachmentInfo> attachment_info_list;
        public List<string> links;
        
        public MessageInfo(
            string folder_name,
            string sender_address,
            DateTime created_date,
            DateTime received_date,
            Recipients recipients,
            IEnumerable<string> links,
            IEnumerable<AttachmentInfo> attachment_info_list
        ) {
            this.folder_name = folder_name;
            this.sender_address = sender_address;
            
            this.created_date = created_date;
            this.received_date = received_date;
            
            this.to_addresses = (from to_recipient in recipients.To select to_recipient.EmailAddress).ToList();
            this.cc_addresses = (from cc_recipient in recipients.CC select cc_recipient.EmailAddress).ToList();
            this.bcc_addresses = (from bcc_recipient in recipients.BCC select bcc_recipient.EmailAddress).ToList();
            
            this.links = links.ToList();
            this.attachment_info_list = attachment_info_list.ToList();
        }
    }
    
    class Program {
        
        public static List<string> get_html_links(string html_data) {
            var html_document = new HtmlDocument();
            html_document.LoadHtml(html_data);
            
            var a_nodes = html_document.DocumentNode.SelectNodes("//a/@href");
            if (a_nodes is null)
                return new List<string>();

            return (
                from node in a_nodes
                from attribute in node.Attributes.AttributesWithName("href")
                select attribute.Value
            ).ToList();
        }
        
        static void Main(string[] args) {
            if (args.Length != 2) {
                Console.WriteLine("args: <pst_path> <output_path>");
                return;
            }
            
            var email_findings = new List<MessageInfo>();
            using (var file = new PSTFile(args[0])) {
                var folder_stack = new Stack<MailFolder>();
                folder_stack.Push(file.TopOfPST);
                
                // NOTE: I am not making any decision about only parsing sent, received, etc. -- parsing any message in
                // any folder.
                
                while (folder_stack.Count > 0) {
                    var current_folder = folder_stack.Pop();
                    
                    foreach (var sub_folder in current_folder.SubFolders)
                        folder_stack.Push(sub_folder);

                    foreach (var ipm_item in current_folder.GetIpmItems()) {
                        if (!(ipm_item is PSTParse.MessageLayer.Message message))
                            continue;

                        email_findings.Add(
                            new MessageInfo(
                                folder_name: current_folder.DisplayName,
                                sender_address: message.SenderAddress,
                                created_date: message.CreationTime,
                                received_date: message.MessageDeliveryTime,
                                recipients: message.Recipients,
                                links: Program.get_html_links(message.BodyHtml),
                                attachment_info_list: (
                                    !message.HasAttachments
                                    ? new List<AttachmentInfo>()
                                    : (from attachment in message.Attachments select new AttachmentInfo(
                                        filename: attachment.AttachmentLongFileName,
                                        sha256_hash: string.Join(
                                            "", 
                                            SHA256.Create().ComputeHash(attachment.Data).Select(b => b.ToString("x2"))
                                        )
                                    )).ToList()
                                )
                            )
                        );
                    }
                }
            }

            File.WriteAllText(args[1], JsonConvert.SerializeObject(email_findings));
        }
    }
}