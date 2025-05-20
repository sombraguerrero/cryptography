using iGCM;
using LoremNETCore;
using System.Text;

namespace GCM_Form
{
    public partial class Form1 : Form
    {
        private readonly IKeyStorage _keyStorage;
        public Form1(IKeyStorage keyStorage)
        {
            _keyStorage = keyStorage;
            InitializeComponent();
        }

        private void asTxtBtn_Click(object sender, EventArgs e)
        {
            if (encBtn.Checked)
            {
                //outputTxt.Text = Convert.ToBase64String(EncryptData(inputTxt.Text, Convert.FromBase64String(Settings.Default.myKey)));
                outputTxt.Text = Convert.ToBase64String(IGCM.EncryptData(inputTxt.Text, _keyStorage.Key));
            }
            else
            {
                //outputTxt.Text = Encoding.UTF8.GetString(DecryptData(inputTxt.Text, Convert.FromBase64String(Settings.Default.myKey)));
                outputTxt.Text = Encoding.UTF8.GetString(IGCM.DecryptData(inputTxt.Text, _keyStorage.Key));
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.ShowDialog() == DialogResult.OK)
            {
                if (encBtn.Checked)
                {
                    inputTxt.Text = openFileDialog1.FileName;
                    //ReadOnlySpan<byte> myData = EncryptData(File.ReadAllBytes(inputTxt.Text), Convert.FromBase64String(Settings.Default.myKey));
                    ReadOnlySpan<byte> myData = IGCM.EncryptData(File.ReadAllBytes(inputTxt.Text), _keyStorage.Key);
                    outputTxt.Text = saveFileDialog1.FileName;
                    File.WriteAllBytes(outputTxt.Text, myData.ToArray());
                }
                else
                {
                    inputTxt.Text = openFileDialog1.FileName;
                    //ReadOnlySpan<byte> myData = DecryptData(File.ReadAllBytes(inputTxt.Text), Convert.FromBase64String(Settings.Default.myKey));
                    ReadOnlySpan<byte> myData = IGCM.DecryptData(File.ReadAllBytes(inputTxt.Text), _keyStorage.Key);
                    outputTxt.Text = saveFileDialog1.FileName;
                    File.WriteAllBytes(outputTxt.Text, myData.ToArray());
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            HttpClient client = new HttpClient();
            Random rand = new Random();
            inputTxt.Text = Generate.Paragraph(20, 30, 3, 5);
        }
    }
}
