import os
import requests
import time
import secrets
import itertools
import json

#
# This script is designed to be executed outside the JobHandler as an independent
# client. Create a file to define the environment variables as shown below,
# needed and source it prior to executing the script.
#
'''
    export JOB_CANNON_API_BASE_URL=https://[dev_domain]/easyweb/api
    export JOB_CANNON_USERNAME=your_username
    export JOB_CANNON_PASSWORD=your_password
    export JOB_CANNON_DURATION_MIN=60
    export JOB_CANNON_DURATION_MAX=90
    export JOB_CANNON_MAX_JOBS=30
    export JOB_CANNON_LAUNCH_SEPARATION=0.1
    export JOB_CANNON_MAX_LAUNCH_PROBABILITY=100
'''

# Import credentials and config from environment variables
config = {
    'auth_token': '',
    'apiBaseUrl': os.environ['JOB_CANNON_API_BASE_URL'],
    'username': os.environ['JOB_CANNON_USERNAME'],
    'password': os.environ['JOB_CANNON_PASSWORD'],
    'database': os.environ['JOB_CANNON_DATABASE'].lower(),
    'duration_min': os.environ['JOB_CANNON_DURATION_MIN'],
    'duration_max': os.environ['JOB_CANNON_DURATION_MAX'],
    'launch_probability': os.environ['JOB_CANNON_MAX_LAUNCH_PROBABILITY'],
    'launch_separation': os.environ['JOB_CANNON_LAUNCH_SEPARATION'],
    'max_jobs': os.environ['JOB_CANNON_MAX_JOBS'],
}
# All or nothing customization from environment variables
try:
    config['duration_min'] = int(os.environ['JOB_CANNON_DURATION_MIN'])
    config['duration_max'] = int(os.environ['JOB_CANNON_DURATION_MAX'])
    config['launch_probability'] = int(
        os.environ['JOB_CANNON_MAX_LAUNCH_PROBABILITY'])
    config['launch_separation'] = float(
        os.environ['JOB_CANNON_LAUNCH_SEPARATION'])
    config['max_jobs'] = int(os.environ['JOB_CANNON_MAX_JOBS'])
except:
    pass

# print(config)

ra_decs = [
    [21.58813, 3.48611],
    [21.59813, 3.58611],
    [21.57813, 3.68611],
    [21.57213, 3.78611],
    [36.60840, -15.68889],
    [36.63840, -15.66889],
    [36.66840, -15.68889],
    [36.67840, -15.65889],
    [46.27566, -34.25000],
    [46.28566, -34.25500],
    [46.29566, -34.25600],
    [46.27566, -34.25900],
    [21.24000, -11.77],
    [10.149718140063804,-44.789580021829515],
    [9.369964937607078,-44.77674846543062],
    [9.315183098942187,-44.77894070041487],
    [8.875985862630946,-44.7625425199296],
    [9.326514557928627,-44.729809409478555],
    [9.3927939619445,-44.767106590488595],
    [9.957942354547745,-44.75215940860701],
    [9.39704617822661,-44.72272860960975],
    [9.424383952868281,-44.736188743633285],
    [10.033019435833944,-44.688616845188484],
    [9.400433245188907,-44.70407755559758],
    [9.328228041760042,-44.6125030198486],
    [9.389674824843516,-44.68386880795151],
    [10.015763280899689,-44.669350966403854],
    [9.050755639167868,-44.5593259410309],
    [8.533157193619392,-44.58156578707379],
    [8.551184915869838,-44.53301425769099],
    [9.043727070995093,-44.59391162558379],
    [9.362123715268902,-44.63296360940012],
    [9.296170550740829,-44.60913843654165],
    [9.899111190489435,-44.572862235642305],
    [9.327939961809916,-44.57812495998348],
    [9.95675452332486,-44.477709814516714],
    [9.05061959824268,-44.54256111647747],
    [9.957440599482391,-44.54182207158411],
    [10.007745015680715,-44.552917636141494],
    [9.575208816361046,-44.45057386506081],
    [9.062414340220526,-44.57448467438516],
    [10.333354355521529,-44.5698086004109],
    [9.251051475408428,-44.56844489991183],
    [9.368261547630006,-44.57074631388274],
    [9.375483346417882,-44.54122862799648],
    [9.92914615516279,-44.55102124438727],
    [9.498161712538868,-44.578539451261705],
    [9.302749364939881,-44.5361373403848],
    [9.581180434737592,-44.53005347157625],
    [9.099528279389418,-44.56587259494718],
    [10.021365942237228,-44.525256735907895],
    [9.28661676391004,-44.56662066944971],
    [8.928462057130451,-44.39577339530154],
    [9.310744907162206,-44.51686788913989],
    [8.893357025021583,-44.541067186829814],
    [9.925036654234361,-44.46967602438461],
    [9.897905779311657,-44.488376085059194],
    [8.91754752921025,-44.51212540956519],
    [8.85389156245625,-44.517864396470564],
    [10.205712319843435,-44.131736461487186],
    [9.647114559248546,-44.49632403095206],
    [9.883522437401224,-44.504476108049055],
    [10.048364533505621,-44.52632802890756],
    [9.619833049664132,-44.53337593759114],
    [8.873107569952978,-44.49921853378226],
    [9.55122617716273,-44.51209841537907],
    [9.370502045748799,-44.49911742198755],
    [10.067475497768314,-44.51597084391566],
    [9.021402626531767,-44.514581508902815],
    [9.612719701571706,-44.504958348279196],
    [9.232953641790449,-44.49407470875051],
    [8.598596665921125,-44.47627601076943],
    [9.96550470804071,-44.49850939111445],
    [9.921031795079708,-44.49708738063946],
    [8.739345344846807,-44.48564443666965],
    [10.065789613075912,-44.46303320707676],
    [10.080094361959388,-44.485942202010456],
    [10.010483303605659,-44.48725732531789],
    [10.050664257767059,-44.49562198110094],
    [9.012029664739586,-44.49848747555167],
    [9.039999599644688,-44.493798207784295],
    [9.944885761654778,-44.44779897762647],
    [8.929669522539674,-44.4303181601836],
    [9.980481452440984,-44.43389719481697],
    [9.748308849629858,-44.488310836432206],
    [8.584877755402681,-44.44230792054087],
    [8.83275682339744,-44.470588074786626],
    [8.934396303295465,-44.456014407099424],
    [9.529037711108545,-44.472265477669296],
    [8.942216485884835,-44.47218227471774],
    [9.668541227895865,-44.476495495661354],
    [10.327682124204898,-44.45553386104601],
    [9.249819005758665,-44.465288969712454],
    [8.898539698205091,-44.459458614956596],
    [8.87313775862972,-44.46138932489911],
    [8.981877102108081,-44.464864971605586],
    [10.34014834969819,-44.43823055681797],
    [9.521614347294237,-44.257122199011825],
    [9.69080878284708,-44.45986906073657],
    [10.3739714202984,-44.436781329838496],
    [10.072752755124109,-44.43656326783252],
    [9.636423087643749,-44.441757278496155],
    [8.952203441151523,-44.44249550298892],
    [10.239813454710385,-44.43284443852267],
    [9.957690362801143,-44.42764845681658],
    [10.104383923470294,-44.423495472892206],
    [9.96824626059656,-44.40901505309736],
    [10.113893796727542,-44.38193722592042],
    [9.492997493484888,-44.36670961872193],
    [9.906858911382834,-44.334590877353925],
    [10.362197225012515,-44.27276436510292],
    [10.41207502519823,-44.287232415137815],
    [10.039741229790428,-44.26486376562299],
    [9.573971247702863,-44.26190161742023],
    [10.323994805291486,-44.28407449801607],
    [10.449342205186943,-44.258865225075326],
    [9.952955004672216,-44.27920803892847],
    [9.182693274317545,-44.180055363117816],
    [9.65435263638841,-43.74930406576156],
    [8.801389900338643,-44.243009742893335],
    [10.407755417378736,-44.254773015122474],
    [10.306825873249776,-44.258884150894666],
    [8.83184300599613,-44.23726216208043],
    [8.891767795367576,-44.17909902429277],
    [9.978770573598553,-44.24149656643066],
    [10.279918337547073,-44.19842191888467],
    [9.163918014333607,-44.19963918552201],
    [10.040692098229032,-44.228482398500525],
    [10.244211042989106,-44.16466218307179],
    [10.081038692860668,-44.24971416334993],
    [9.064100815277166,-44.23072539164944],
    [9.168186944307777,-44.21841444183676],
    [10.312103883402996,-44.23541577895453],
    [10.099893281224299,-44.22758760683106],
    [9.916457104531789,-44.21559681952642],
    [9.970266421986969,-44.21896708932423],
    [9.274252046994473,-44.21989375025959],
    [10.25841030304077,-44.218604390157886],
    [8.908639025334306,-44.13409498639644],
    [9.211929811224312,-44.215659765577335],
    [10.356899469573198,-44.213165600066795],
    [9.013942298934852,-44.18638749408133],
    [9.108451237561136,-44.19315259795284],
    [9.923453917460298,-44.1939600529522],
    [8.679546522211446,-44.20758305579508],
    [9.33228498373053,-44.21071648343913],
    [10.241225852353132,-44.20413895808739],
    [10.073631586602275,-44.198855535585686],
    [8.745103194136147,-44.18377085260446],
    [10.327931495192706,-44.18949061571695],
    [10.043691802867254,-44.195901585176046],
    [9.087971315113498,-44.146127172612765],
    [10.124456388735863,-44.19269075263602],
    [8.904464479710471,-44.10481846404672],
    [9.130615118543911,-44.17158217542791],
    [9.172871143450903,-44.144400882182325],
    [10.214959834424896,-44.06888418394077],
    [9.255291089737266,-44.133579106480965],
    [10.062058338754241,-44.10597015687143],
    [9.917566019921848,-44.03121503641414],
    [8.969241837065413,-44.116165187563695],
    [9.69770266993659,-44.053419391366965],
    [9.597322565863918,-44.07288885050664],
    [9.627550610792763,-44.057095770417355],
    [9.983030973086995,-44.049710049638456],
    [9.220268580884726,-44.07065631575258],
    [9.18553178058619,-43.80537571093571],
    [9.857875084296845,-42.98428985491863],
    [8.974683573551937,-44.780209742223995],
    [10.011691543773388,-43.06186638542903],
    [9.93554777447604,-43.07696569826923],
    [9.265535903873666,-43.11249275192693],
    [9.98412766795347,-43.254873773769184],
    [8.444010128053291,-43.290428186589224],
    [9.607783657686692,-43.537977149568555],
    [9.678991888494275,-43.54775900733795],
    [9.911419561765994,-43.726141056084025],
    [10.360974354378165,-43.72652242934699],
    [9.718414062143703,-43.73427502000046],
    [9.545955201633035,-43.74872670916701],
    [10.377175852358212,-43.743752514252364],
    [10.051027399133941,-43.74684628820374],
    [9.241536890953773,-43.77844629010195],
    [9.913352036116859,-43.755067680488565],
    [9.679739128559657,-43.75094770586067],
    [8.71072828045335,-43.78605122755096],
    [9.967809289965945,-43.77549495723816],
    [9.700342612901258,-43.819834349050076],
    [10.105538021695075,-43.78480566744357],
    [10.087801470447477,-43.807413916210784],
    [10.130398868991591,-43.80967968217192],
    [10.0052258438395,-43.75026466375325],
    [9.205099758052775,-43.832870820653426],
    [10.077469305849391,-43.87458063772133],
    [10.045862881973445,-43.83100937261331],
    [9.57757461382929,-43.74509078603622],
    [10.024694527139726,-43.8389282788765],
    [10.020400960216293,-43.8585698985951],
    [9.662688444150863,-43.68177665077127],
    [9.03430771210408,-43.88726061507986],
    [8.900596432576393,-43.89552300702709],
    [8.834489891769673,-43.901073714969286],
    [9.861823514548092,-43.9123187273467],
    [9.63467937117086,-43.92661824696303],
    [8.875371844339849,-43.93265810448908],
    [9.999734485355992,-43.93574051991598],
    [10.044616226903887,-43.940923541548656],
    [9.648407114968169,-43.95431656744636],
    [9.73676758514272,-43.959154367721396],
    [10.034433153468042,-43.958199911526805],
    [10.362289341463153,-43.95584206436941],
    [9.957790385259406,-43.97303641382971],
    [9.933190313558626,-43.967420567109215],
    [9.632188113342332,-43.97688014069091],
    [9.584033349890676,-43.977413420720175],
    [9.707551715862328,-43.97885662446959],
    [9.984815434018797,-43.98056332854049],
    [9.75184311858128,-43.98308952577758],
    [8.98901909601777,-43.99071962642002],
    [10.0368374750774,-43.98424980697348],
    [9.343285833269816,-43.99673454536623],
    [9.638657531146468,-43.996993922034456],
    [8.955943425257455,-44.00714750831496],
    [9.600068883953817,-44.01778312397387],
    [9.987102611035391,-43.99988334940448],
    [9.961990958028618,-44.00933963799381],
    [10.049580587067645,-44.01376811061442],
    [10.002760397446195,-44.02265010074431],
    [9.613159417904138,-44.0405369223427],
    [10.022886462407895,-44.0437417450057],
    [9.68495755228393,-44.027373565569164],
    [9.942535287426105,-43.126440738718834],
    [8.977379991492995,-42.998765562346684],
    [10.03713904063846,-43.10039679163547],
    [9.96332482799749,-43.08519645966564],
    [10.060830890864825,-43.23530047826503],
    [9.90367804731732,-43.11249720044779],
    [9.976627592741353,-43.105215349917266],
    [9.97842027382718,-43.13100502954688],
    [9.933972028846883,-43.17989680887222],
    [10.00633169288568,-43.17280450757608],
    [9.96861809778981,-43.18533612952392],
    [10.038533273231266,-43.146332226963956],
    [9.80001796589631,-43.163101483434474],
    [10.064402005045856,-43.196544963102674],
    [9.973184298267293,-43.205370921670145],
    [10.106527031164246,-43.21127175994313],
    [10.041469821999604,-43.21232696634123],
    [9.641729993768969,-43.23514636386582],
    [9.61588043977682,-43.21225020069086],
    [9.640547550619882,-43.26283010693494],
    [9.953689161943794,-43.27222905695596],
    [10.079604688825246,-43.45524601898342],
    [8.622353929842857,-43.34745918332946],
    [8.616355585873999,-43.31481393736351],
    [10.100573620652591,-43.26678902678783],
    [10.016272359001784,-43.23234094166954],
    [9.206348300322214,-43.355667304619104],
    [9.712026489149054,-43.29412025290977],
    [9.685270979317144,-43.295490429958065],
    [10.033033571204825,-43.28511637010304],
    [10.102633038805013,-43.45592603260726],
    [9.189067044173749,-43.33624585328831],
    [8.841148869485608,-43.54194844343471],
    [9.32400217988641,-43.49635288879882],
    [9.116263548317157,-43.47279202662713],
    [9.311253544281074,-43.529378213367266],
    [9.227842074299842,-43.38166755430993],
    [10.049263591560342,-43.52290014245924],
    [10.014242463111426,-43.44771643633245],
    [8.734141810621804,-43.45956367010181],
    [9.655840704692128,-43.44807677601752],
    [10.031531049949379,-43.42570864294398],
    [9.951468254255932,-43.43787401209079],
    [9.968487303487732,-43.424938122326445],
    [10.108064247366658,-43.41426315109815],
    [10.03945475988101,-43.465238099099324],
    [10.055003171366161,-43.4405512306663],
    [9.974815504411515,-43.46189819022963],
    [9.51565846001386,-43.4968801563356],
    [9.471557780063138,-43.47565884506506],
    [10.013578027795262,-43.498303196840475],
    [8.779411519339448,-43.526054053504005],
    [9.64463444382301,-43.485993806041144],
    [9.57501143840881,-43.50650264770615],
    [10.06608085351843,-43.50039196549986],
    [9.989740505181942,-43.48582322586748],
    [10.044182393215982,-43.488689831248394],
    [9.25450816449214,-43.506606534222215],
    [9.729616530034257,-43.502887196353804],
    [9.714891963277596,-43.51826415280642],
    [10.019871992039308,-43.525645126745474],
    [9.665856656904314,-43.5269573855569],
    [9.939321762853568,-43.51713311893133],
    [10.117820800552566,-44.874621402209186],
    [10.306421752365319,-43.71134319724547],
    [10.00122307892825,-43.80040075878629],
    [10.045741704496109,-43.77426096411174],
    [10.024960918859225,-43.796191193516286],
    [10.008652363775624,-43.772535335784696],
    [9.608740751888131,-43.70689670547241],
    [10.056492386488546,-43.79338877946738],
    [9.936549698932673,-43.72097168277749],
    [9.896947323023724,-43.69305664796273],
    [10.075548371242583,-43.69369131836742],
    [9.936077367672151,-43.68813749093008],
    [9.960763346330044,-43.69511034694453],
    [9.33623653043358,-43.68935783333825],
    [9.736494584394894,-43.69813684168067],
    [9.334625204972724,-43.759021282256086],
    [9.203931475922428,-43.744418913020105],
    [10.16938204718441,-43.76312442381489],
    [10.28800669964208,-43.78953865070164],
    [9.937418801531933,-43.77541326288119],
    [9.219566907715125,-43.7676796089075],
    [9.612762247713865,-43.73105015733537],
    [9.622631411236545,-43.76288284154034],
    [9.97894019401139,-43.81083333988035],
]

# These coadd IDs are valid for release Y3A2:
#     SELECT COADD_OBJECT_ID FROM Y3_GOLD_2_2 where ROWNUM < 20
# Coadd IDs from the Y6A1 release can be found by:
#     SELECT COADD_OBJECT_ID FROM Y6_GOLD_1_1 where ROWNUM < 20
coadds = [
    '61407318',
    '61407322',
    '61407330',
    '61407332',
    '61407340',
    '61407380',
    '61407409',
    '61407410',
    '61407412',
    '61407424',
    '61407430',
    '61407435',
    '61407478',
    '61407507',
    '61407519',
    '61407550',
    '61407559',
    '61407563',
    '61407582'
]

def login():
    # Login to obtain an auth token
    r = requests.post(
        '{}/login'.format(config['apiBaseUrl']),
        data={
            'username': config['username'],
            'password': config['password'],
            'database': config['database']
        }
    )
    # Store the JWT auth token
    token = r.json()['token']
    config['auth_token'] = token
    return token


def submit_test_job():
    # Submit a test job
    test_duration = 10  # seconds
    r = requests.put(
        '{}/job/submit'.format(config['apiBaseUrl']),
        data={
            'username': config['username'],
            'job': 'test',
            'time': test_duration
        },
        headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
    )
    job_id = r.json()['jobid']
    print(r.text)
    return job_id


def monitor_test_job(job_id):
    # Monitor the test job status
    max_loops = 5
    idx = 0
    while idx < max_loops:
        idx = idx + 1

        r = requests.post(
            '{}/job/status'.format(config['apiBaseUrl']),
            data={
                'job-id': job_id
            },
            headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
        )
        # print(r.text)
        r = r.json()
        status = r['jobs'][0]['job_status']
        print('Status: {}'.format(status))
        if status == 'success' or status == 'failure':
            break
        time.sleep(3)


def launch_multiple_jobs(job_type='test', randomize_each=False):
    job_idx = 0
    loop_idx = 0
    data = None
    while job_idx < config['max_jobs']:
        # Submit job with 50% probability per second
        if secrets.choice(range(0, 100)) < config['launch_probability']:
            # Job type: test
            if job_type == 'test':
                # Select a random job duration
                duration = secrets.choice(
                    range(config['duration_min'], config['duration_max']))
                if not data or randomize_each:
                    data = {
                        'username': config['username'],
                        'job': 'test',
                        'time': duration
                    }
            # Job type: cutout
            elif job_type == 'cutout':
                # Choose random set of colors for FITS
                fits_band = secrets.choice(list('grizy'))
                colors_fits = [fits_band]
                for i in range(0,secrets.choice(range(1,3))):
                    while fits_band in colors_fits:
                        fits_band = secrets.choice(list('grizy'))
                    colors_fits.append(fits_band)
                colors_fits = sorted(colors_fits)
                colors_fits = ''.join(colors_fits)
                # Choose from combinations of
                colors_rgb = []
                combinations = []
                for combination in list(itertools.combinations(list('grizy'), 3)):
                    combinations.append(combination)
                colors_rgb = ','.join(secrets.choice(combinations))

                if not data or randomize_each:
                    data = {
                        'username': config['username'],
                        'job': 'cutout',
                        'db': config['database'],
                        'xsize': secrets.choice([0.1,0.5,1.0,5.0]),
                        'ysize': secrets.choice([0.1,0.5,1.0,5.0]),
                        'make_fits': secrets.choice(['true', 'false']),
                        'make_pngs': secrets.choice(['true', 'false']),
                        'make_tiffs': secrets.choice(['true', 'false']),
                        'make_rgb_lupton': secrets.choice(['true', 'false']),
                        'make_rgb_stiff': secrets.choice(['true', 'false']),
                        'return_list': secrets.choice(['true', 'false']),
                        'colors_fits': colors_fits,
                        'colors_rgb': colors_rgb,
                    }
                    ## TODO: Only use RA/DEC until we can specify a list of COADD IDs for DR1/DR2 releases
                    if config['database'] == 'desdr':
                        data['release'] = secrets.choice(['DR1', 'DR2'])
                    else:
                        data['release'] = secrets.choice(['Y6A1', 'Y3A2'])
                        
                    data['positions'] = f'''RA,DEC\n'''
                    # for i in range(1,secrets.choice(range(len(ra_decs)-6, len(ra_decs)-1))):
                    for i in range(1,secrets.choice(range(20,300))):
                        ra_dec = secrets.choice(ra_decs)
                        data['positions'] += f'''{ra_dec[0]},{ra_dec[1]}\n'''
                    # ## Select either RA/DEC
                    # if secrets.choice(['coadds', 'ra_decs']) == 'ra_decs':
                    #     if config['database'] == 'desdr':
                    #         data['release'] = secrets.choice(['DR1', 'DR2'])
                    #     else:
                    #         data['release'] = secrets.choice(['Y6A1', 'Y3A2'])
                    #     ra_dec = secrets.choice(ra_decs)
                    #     data['ra'] = ra_dec[0]
                    #     data['dec'] = ra_dec[1]
                    # # or Coadd IDs
                    # else:
                    #     data['release'] = secrets.choice(['Y3A2'])
                    #     data['coadd'] = secrets.choice(coadds)

            # Submit job
            r = requests.put(
                '{}/job/submit'.format(config['apiBaseUrl']),
                data=data,
                headers={'Authorization': 'Bearer {}'.format(
                    config['auth_token'])}
            )
            print(json.dumps(data, indent=2))
            if r.json()['status'] == 'ok':
                job_idx = job_idx + 1
                job_id = r.json()['jobid']
                print('Job "{}" started at cycle {}.'.format(job_id, loop_idx))
            else:
                print(r.json()['message'])
                print('Error submitting job at cycle {}'.format(loop_idx))

        loop_idx = loop_idx + 1
        time.sleep(config['launch_separation'])

if __name__ == '__main__':
    login()
    launch_multiple_jobs(job_type='cutout', randomize_each=True)
